/**
 * The new KS256 inputs at the MCP boundary: schema shape, the
 * exactly-one-of refinement, and an attested verify end to end over the
 * in-memory transport. Evidence is generated at run time; fetch is forbidden
 * by the global setup, so a pass also shows the tools never call the chain.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer } from "../../src/node/server.js";
import {
  buildKs256Fixture,
  encodedAttestationFor,
} from "../core/ks256-fixture.js";

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");
const PAYLOAD = new TextEncoder().encode("mcp ks256 statement");

let client: Client;

beforeAll(async () => {
  const [c, s] = InMemoryTransport.createLinkedPair();
  await createServer().connect(s);
  client = new Client({ name: "ks256-test", version: "0" });
  await client.connect(c);
});

afterAll(async () => {
  await client.close();
});

async function fixture() {
  const inner = new Uint8Array(await crypto.subtle.digest("SHA-256", PAYLOAD));
  return buildKs256Fixture(inner, { contractRoot: true });
}

describe("advertised schema", () => {
  it("offers ks256Attestation on both verify tools, and names the sources", async () => {
    const { tools } = await client.listTools();
    for (const name of ["verify_receipt", "verify_grant_receipt"]) {
      const tool = tools.find((t) => t.name === name);
      const props = (tool?.inputSchema as { properties: Record<string, any> })
        .properties;
      expect(props.ks256Attestation).toBeDefined();
      expect(props.ks256Attestation.description).toMatch(
        /fetch_ks256_attestation/,
      );
      expect(props.ks256Attestation.description).toMatch(
        /fetch-ks256-attestation/,
      );
    }
    const json = JSON.stringify(tools);
    expect(json).toContain("ks256Address");
    expect(json).toContain("forestGenesis");
  });
});

describe("verify_receipt with a KS256 contract root", () => {
  it("passes with an attestation and surfaces the attested block", async () => {
    const fx = await fixture();
    const res = await client.callTool({
      name: "verify_receipt",
      arguments: {
        receipt: { b64: b64(fx.receipt) },
        payload: { b64: b64(PAYLOAD) },
        entryId: fx.entryId,
        trust: {
          root: "known-log-key",
          ks256Address: fx.rootAddressHex,
          forestGenesis: { b64: b64(fx.genesis) },
        },
        ks256Attestation: { b64: b64(encodedAttestationFor(fx)) },
      },
    });
    expect(res.isError).toBeFalsy();
    const r = res.structuredContent as {
      ok: boolean;
      ks256Attestation?: { blockNumber: string; chainId: string };
    };
    expect(r.ok).toBe(true);
    expect(r.ks256Attestation).toMatchObject({
      blockNumber: "1234",
      chainId: "84532",
    });
    const text = (res.content as { text: string }[])[0]?.text ?? "";
    expect(text).toMatch(/PASS/);
  });

  it("fails with a named reason when no attestation is given", async () => {
    const fx = await fixture();
    const res = await client.callTool({
      name: "verify_receipt",
      arguments: {
        receipt: { b64: b64(fx.receipt) },
        payload: { b64: b64(PAYLOAD) },
        entryId: fx.entryId,
        trust: { root: "known-log-key", ks256Address: fx.rootAddressHex },
      },
    });
    const r = res.structuredContent as { ok: boolean; reason: string };
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("ks256_root_not_recovered");
    expect((res.content as { text: string }[])[0]?.text).toMatch(
      /ks256_root_not_recovered/,
    );
  });
});

describe("input validation", () => {
  const base = async () => {
    const fx = await fixture();
    return {
      fx,
      args: {
        receipt: { b64: b64(fx.receipt) },
        payload: { b64: b64(PAYLOAD) },
        entryId: fx.entryId,
      },
    };
  };

  it("refuses keyXy together with ks256Address", async () => {
    const { fx, args } = await base();
    const res = await client.callTool({
      name: "verify_receipt",
      arguments: {
        ...args,
        trust: {
          root: "known-log-key",
          keyXy: { b64: b64(new Uint8Array(64).fill(1)) },
          ks256Address: fx.rootAddressHex,
        },
      },
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/exactly one of keyXy/);
  });

  it("refuses neither keyXy nor ks256Address", async () => {
    const { args } = await base();
    const res = await client.callTool({
      name: "verify_receipt",
      arguments: { ...args, trust: { root: "known-log-key" } },
    });
    expect(res.isError).toBe(true);
  });

  it("refuses a malformed ks256Address", async () => {
    const { args } = await base();
    const res = await client.callTool({
      name: "verify_receipt",
      arguments: {
        ...args,
        trust: { root: "known-log-key", ks256Address: "0x1234" },
      },
    });
    expect(res.isError).toBe(true);
  });

  it("reports malformed attestation bytes as an input failure, not a verdict about the receipt", async () => {
    const { fx, args } = await base();
    const res = await client.callTool({
      name: "verify_receipt",
      arguments: {
        ...args,
        trust: { root: "genesis", genesis: { b64: b64(fx.genesis) } },
        ks256Attestation: { b64: b64(new Uint8Array([9, 9, 9])) },
      },
    });
    const r = res.structuredContent as {
      ok: boolean;
      stage: string;
      reason: string;
    };
    expect(r.ok).toBe(false);
    expect(r.stage).toBe("parse");
    expect(r.reason).toMatch(/ks256Attestation is not a valid/);
  });
});
