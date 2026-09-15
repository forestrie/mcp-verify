/**
 * `verify --self` and the `verify_self` MCP tool, over a REAL bundle —
 * the frozen `test/fixtures/self-bundle/`
 * copied into a private, disposable directory.
 *
 * A private directory rather than the real `fixtures/self/`: that path is
 * generated at release time and gitignored (docs/self-registration.md), so
 * every OTHER test in this suite assumes it is absent, and vitest may run
 * test files concurrently — mutating the real, shared path here would race
 * against them. `MCP_VERIFY_SELF_FIXTURES_DIR` (`src/node/fixtures.ts`)
 * exists for exactly this: it retargets `loadSelfBundle`/`listSelfFixtures`
 * at a directory this file owns, with `fixtures/self/`'s own loading logic
 * completely unchanged. `process.env` mutations here do not cross into other
 * test files' worker threads (each gets its own copy at spawn), so this is
 * safe even under parallel test execution.
 */
import { cpSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer } from "../../src/node/server.js";
import { readSelfFixture } from "../../src/node/fixtures.js";
import { runVerifySelf } from "../../src/node/self-cli.js";
import { SELF_BUNDLE_DIR } from "../core/self-bundle.js";

const ENV_VAR = "MCP_VERIFY_SELF_FIXTURES_DIR";

function linesOf(): { write: (line: string) => void; lines: string[] } {
  const lines: string[] = [];
  return { write: (line) => lines.push(line), lines };
}

describe("verify --self / verify_self — the bundle is absent", () => {
  beforeAll(() => {
    // An empty, never-populated directory: the bundle-absent state, without
    // depending on whatever fixtures/self/ happens to hold on this machine.
    const empty = mkdtempSync(join(tmpdir(), "mcp-verify-self-absent-"));
    process.env[ENV_VAR] = empty;
  });

  afterAll(() => {
    const dir = process.env[ENV_VAR];
    delete process.env[ENV_VAR];
    if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
  });

  it("runVerifySelf exits 2 and says why, never throws", async () => {
    const { write, lines } = linesOf();
    const code = await runVerifySelf(write);
    expect(code).toBe(2);
    expect(lines.join("\n")).toContain(
      "this checkout was not produced by a release",
    );
  });
});

describe("verify --self / verify_self — the bundle is populated from the frozen copy", () => {
  let dir: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "mcp-verify-self-bundle-"));
    for (const name of readdirSync(SELF_BUNDLE_DIR)) {
      if (name === "PROVENANCE.md") continue; // not part of the generated bundle
      cpSync(join(SELF_BUNDLE_DIR, name), join(dir, name));
    }
    process.env[ENV_VAR] = dir;
  });

  afterAll(() => {
    delete process.env[ENV_VAR];
    rmSync(dir, { recursive: true, force: true });
  });

  it("runVerifySelf exits 0 and narrates PASS, root, and the un-walked chain", async () => {
    const { write, lines } = linesOf();
    const code = await runVerifySelf(write);
    const text = lines.join("\n");
    expect(code).toBe(0);
    expect(text).toContain("verify-self: PASS");
    expect(text).toContain("root=known-log-key");
    expect(text).toContain("self_chain_not_walked");
    expect(text).toContain("@forestrie/mcp-verify@0.2.0");
  });

  describe("the MCP tool and resources", () => {
    let client: Client;

    beforeAll(async () => {
      const [clientTransport, serverTransport] =
        InMemoryTransport.createLinkedPair();
      const server = createServer();
      await server.connect(serverTransport);
      client = new Client({ name: "self-test", version: "0" });
      await client.connect(clientTransport);
    });

    afterAll(async () => {
      await client.close();
    });

    it("tools/list includes verify_self", async () => {
      const { tools } = await client.listTools();
      expect(tools.map((t) => t.name)).toContain("verify_self");
    });

    it("verify_self passes at the default root, with structured + text", async () => {
      const res = await client.callTool({
        name: "verify_self",
        arguments: {},
      });
      const structured = res.structuredContent as {
        ok: boolean;
        root: string;
        self: {
          statementSignature: string;
          payloadMatchesProvenance: boolean;
        };
      };
      expect(structured.ok).toBe(true);
      expect(structured.root).toBe("known-log-key");
      expect(structured.self.statementSignature).toBe("ok");
      expect(structured.self.payloadMatchesProvenance).toBe(true);

      const content = res.content as { text: string }[];
      expect(content[0]?.text).toContain("root=known-log-key");
      expect(content[0]?.text).toContain(
        "split-view not answered at this root",
      );
    });

    it("registers forestrie://self/… resources that read back the bundled bytes", async () => {
      const { resources } = await client.listResources();
      const uris = resources.map((r) => r.uri);
      expect(uris).toContain("forestrie://self/receipt.cbor");
      expect(uris).toContain("forestrie://self/provenance.json");

      const res = await client.readResource({
        uri: "forestrie://self/receipt.cbor",
      });
      const first = res.contents[0];
      const blob = (first as { blob?: string }).blob;
      expect(typeof blob).toBe("string");
      expect(Buffer.from(blob as string, "base64")).toEqual(
        Buffer.from(readSelfFixture("receipt.cbor")),
      );
    });
  });
});
