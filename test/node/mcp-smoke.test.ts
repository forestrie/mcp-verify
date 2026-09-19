/**
 * The MCP surface, over the SDK's in-memory transport pair.
 *
 * In-memory rather than a spawned process: it is faster and it exercises the
 * same `Server`/`Client` protocol code. The one thing it CANNOT catch is a
 * stray `console.log` corrupting the stdio framing — that needs a real
 * process, and it lives in the publish-dry-run CI job and in
 * `pnpm run check:stdio-clean`.
 *
 * This file runs under the forbidden-fetch global, so it is simultaneously
 * the no-network proof at the MCP layer, for every tool call.
 */
import { readFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";
import { createServer } from "../../src/node/server.js";
import {
  goldenCommittedGrant,
  goldenEntryId,
  readFixture,
} from "../../src/node/fixtures.js";
import { verifyOutputShape } from "../../src/node/tools.js";

const repoRoot = new URL("../../", import.meta.url).pathname;
const pkg = JSON.parse(readFileSync(`${repoRoot}package.json`, "utf8")) as {
  version: string;
};

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");

let client: Client;

beforeAll(async () => {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const server = createServer();
  await server.connect(serverTransport);
  client = new Client({ name: "mcp-verify-test", version: "0" });
  await client.connect(clientTransport);
});

afterAll(async () => {
  await client.close();
});

describe("initialize", () => {
  /**
   * The version is read from package.json here so that a forgotten bump fails
   * as a red test rather than as a lie in `initialize`'s serverInfo.
   */
  it("reports the package version", () => {
    expect(client.getServerVersion()).toMatchObject({
      name: "forestrie-mcp-verify",
      version: pkg.version,
    });
  });

  it("advertises tools and resources", () => {
    const caps = client.getServerCapabilities();
    expect(caps?.tools).toBeDefined();
    expect(caps?.resources).toBeDefined();
  });
});

describe("tools/list", () => {
  it("returns exactly the four tools", async () => {
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([
      "decode_receipt",
      "verify_grant_receipt",
      "verify_receipt",
      "verify_self",
    ]);
  });

  it("every tool advertises an outputSchema", async () => {
    const { tools } = await client.listTools();
    for (const t of tools) {
      expect(t.outputSchema, t.name).toBeDefined();
      expect(t.outputSchema?.type, t.name).toBe("object");
      expect(t.inputSchema.type, t.name).toBe("object");
    }
  });

  /**
   * O2 in assertion form: the SDK converted zod-4 schemas without
   * `z.toJSONSchema()` at the call site. If a future SDK regresses that path,
   * the tools lose their schemas silently — unless this fails.
   */
  it("the zod-4 discriminated union rendered as JSON Schema", async () => {
    const { tools } = await client.listTools();
    const verify = tools.find((t) => t.name === "verify_grant_receipt");
    const trust = (
      verify?.inputSchema.properties as Record<string, { oneOf?: unknown[] }>
    ).trust;
    expect(trust?.oneOf).toHaveLength(4);
  });

  it("every tool is annotated read-only and closed-world", async () => {
    const { tools } = await client.listTools();
    for (const t of tools) {
      expect(t.annotations?.readOnlyHint, t.name).toBe(true);
      expect(t.annotations?.openWorldHint, t.name).toBe(false);
    }
  });
});

describe("resources/list", () => {
  it("includes the golden receipt", async () => {
    const { resources } = await client.listResources();
    const uris = resources.map((r) => r.uri);
    expect(uris).toContain("forestrie://fixtures/golden/grant-receipt.cbor");
    expect(uris).toContain("forestrie://fixtures/golden/grant-genesis.cbor");
    expect(uris).toContain("forestrie://fixtures/golden/manifest.json");
  });

  it("does not register the forestrie://self namespace when fixtures/self/ is absent", async () => {
    const { resources } = await client.listResources();
    // fixtures/self/ is generated at release time and gitignored (never
    // committed), so a normal checkout has none of these files and this
    // package registers no resource that would resolve to nothing.
    // test/node/self.test.ts covers the populated case.
    expect(
      resources.filter((r) => r.uri.startsWith("forestrie://self/")),
    ).toEqual([]);
  });

  it("a fixture resource reads back the exact bundled bytes", async () => {
    const res = await client.readResource({
      uri: "forestrie://fixtures/golden/grant-receipt.cbor",
    });
    const first = res.contents[0];
    expect(first).toBeDefined();
    const blob = (first as { blob?: string }).blob;
    expect(typeof blob).toBe("string");
    expect(Buffer.from(blob as string, "base64")).toEqual(
      Buffer.from(readFixture("golden/grant-receipt.cbor")),
    );
  });
});

describe("tools/call — a real verification over the bundled fixtures", () => {
  it("verify_grant_receipt at the genesis root passes, with structured + text", async () => {
    const res = await client.callTool({
      name: "verify_grant_receipt",
      arguments: {
        receipt: { b64: b64(readFixture("golden/grant-receipt.cbor")) },
        committedGrant: { b64: b64(goldenCommittedGrant()) },
        entryId: goldenEntryId(),
        trust: {
          root: "genesis",
          genesis: { b64: b64(readFixture("golden/grant-genesis.cbor")) },
        },
      },
    });
    const structured = res.structuredContent as { ok: boolean; root: string };
    expect(structured.ok).toBe(true);
    expect(structured.root).toBe("genesis");

    const content = res.content as { type: string; text: string }[];
    expect(content[0]?.type).toBe("text");
    expect(content[0]?.text.length).toBeGreaterThan(0);
    // Never a bare "valid": the summary names the root and the unanswered
    // questions, which is the whole point.
    expect(content[0]?.text).toContain("root=genesis");
    expect(content[0]?.text).toContain("split-view not answered at this root");
  });

  it("the structuredContent validates against the advertised outputSchema", async () => {
    const res = await client.callTool({
      name: "verify_grant_receipt",
      arguments: {
        receipt: { b64: b64(readFixture("golden/grant-receipt.cbor")) },
        committedGrant: { b64: b64(goldenCommittedGrant()) },
        entryId: goldenEntryId(),
        trust: {
          root: "genesis",
          genesis: { b64: b64(readFixture("golden/grant-genesis.cbor")) },
        },
      },
    });
    expect(() =>
      z.object(verifyOutputShape).parse(res.structuredContent),
    ).not.toThrow();
  });

  it("decode_receipt renders the golden receipt and says it verified nothing", async () => {
    const res = await client.callTool({
      name: "decode_receipt",
      arguments: {
        receipt: { b64: b64(readFixture("golden/grant-receipt.cbor")) },
      },
    });
    const structured = res.structuredContent as { byteLength: number };
    expect(structured.byteLength).toBe(118);
    const content = res.content as { text: string }[];
    expect(content[0]?.text).toContain("NOT verified");
  });

  it("base64 is accepted as an alias of b64 on every byte field, with the same result", async () => {
    const res = await client.callTool({
      name: "verify_grant_receipt",
      arguments: {
        receipt: { base64: b64(readFixture("golden/grant-receipt.cbor")) },
        committedGrant: { base64: b64(goldenCommittedGrant()) },
        entryId: goldenEntryId(),
        trust: {
          root: "genesis",
          genesis: { base64: b64(readFixture("golden/grant-genesis.cbor")) },
        },
      },
    });
    expect(res.isError).toBeFalsy();
    expect((res.structuredContent as { ok: boolean }).ok).toBe(true);
  });

  it("a wrong byte shape is refused at the field, naming the accepted shapes", async () => {
    const res = await client.callTool({
      name: "verify_grant_receipt",
      arguments: {
        receipt: { bytes: "AAAA" },
        committedGrant: { b64: b64(goldenCommittedGrant()) },
        entryId: goldenEntryId(),
        trust: { root: "known-log-key", keyXy: { hex: "00" } },
      },
    });
    expect(res.isError).toBe(true);
    const text = (res.content as { text: string }[])[0]?.text ?? "";
    expect(text).toContain("at receipt");
    expect(text).toContain("at trust.keyXy");
    expect(text).toContain("{b64: <standard base64>}");
    expect(text).toContain("{path:");
    expect(text).not.toMatch(/Invalid input at (trust|receipt)$/m);
  });

  it("an unknown root names the four roots", async () => {
    const res = await client.callTool({
      name: "verify_receipt",
      arguments: {
        receipt: { b64: "AAAA" },
        payload: { b64: "AAAA" },
        entryId: goldenEntryId(),
        trust: { root: "nope" },
      },
    });
    expect(res.isError).toBe(true);
    const text = (res.content as { text: string }[])[0]?.text ?? "";
    expect(text).toContain(
      "trust.root must be one of genesis, known-log-key, known-accumulator, checkpoint-chain",
    );
  });

  it("every byte field's advertised description names the accepted shapes", async () => {
    const { tools } = await client.listTools();
    const seen: string[] = [];
    const walk = (node: unknown, path: string): void => {
      if (node === null || typeof node !== "object") return;
      const obj = node as Record<string, unknown>;
      const anyOf = obj["anyOf"];
      if (Array.isArray(anyOf)) {
        const keys = anyOf.flatMap((v) =>
          Object.keys(
            ((v as { properties?: Record<string, unknown> }).properties ??
              {}) as object,
          ),
        );
        if (keys.includes("b64") && keys.includes("path")) {
          seen.push(path);
          expect(keys).toContain("base64");
          expect(String(obj["description"])).toContain(
            "{b64: <standard base64>}",
          );
          expect(String(obj["description"])).toContain("{path:");
          return;
        }
      }
      for (const [k, v] of Object.entries(obj)) walk(v, `${path}.${k}`);
    };
    for (const t of tools) walk(t.inputSchema, t.name);
    // receipt/payload/committedGrant/trust.* across the four tools
    expect(seen.length).toBeGreaterThanOrEqual(8);
  });

  it("an accumulator that does not decode is a structured parse failure, like a bad keyXy — not a thrown message", async () => {
    const res = await client.callTool({
      name: "verify_grant_receipt",
      arguments: {
        receipt: { b64: b64(readFixture("golden/grant-receipt.cbor")) },
        committedGrant: { b64: b64(goldenCommittedGrant()) },
        entryId: goldenEntryId(),
        trust: { root: "known-accumulator", accumulator: { b64: "AQIDBA==" } },
      },
    });
    expect(res.isError).toBeFalsy();
    const structured = res.structuredContent as {
      ok: boolean;
      stage: string;
      reason: string;
      root: string;
    };
    expect(structured.ok).toBe(false);
    expect(structured.stage).toBe("parse");
    expect(structured.root).toBe("known-accumulator");
    expect(structured.reason).toContain(
      "accumulator is not an encodeKnownAccumulator snapshot (4 bytes)",
    );
    const text = (res.content as { text: string }[])[0]?.text ?? "";
    expect(text).toContain("FAILED at parse");
  });

  it("a bad input is a TOOL error, not a verification failure", async () => {
    const res = await client.callTool({
      name: "decode_receipt",
      arguments: { receipt: { b64: "!!!! not base64 !!!!" } },
    });
    expect(res.isError).toBe(true);
    expect(res.structuredContent).toBeUndefined();
    const content = res.content as { text: string }[];
    expect(content[0]?.text).toContain("input error");
  });

  it("a schema-invalid entryId is rejected by the SDK before our code runs", async () => {
    const res = await client.callTool({
      name: "verify_grant_receipt",
      arguments: {
        receipt: { b64: b64(readFixture("golden/grant-receipt.cbor")) },
        committedGrant: { b64: b64(goldenCommittedGrant()) },
        entryId: "NOT-HEX",
        trust: {
          root: "genesis",
          genesis: { b64: b64(readFixture("golden/grant-genesis.cbor")) },
        },
      },
    });
    expect(res.isError).toBe(true);
  });

  /**
   * The absent-bundle case is the normal state for this checkout (see the
   * resources/list test above): `fixtures/self/` is generated at release
   * time and gitignored, so a repo clone has none of it. verify_self must
   * say so clearly rather than throw. test/node/self.test.ts covers the
   * populated case end to end (both the tool and `verify --self`).
   */
  it("verify_self errors clearly when fixtures/self/ is absent", async () => {
    const res = await client.callTool({ name: "verify_self", arguments: {} });
    expect(res.isError).toBe(true);
    expect(res.structuredContent).toBeUndefined();
    const content = res.content as { text: string }[];
    expect(content[0]?.text).toContain(
      "this checkout was not produced by a release",
    );
  });
});
