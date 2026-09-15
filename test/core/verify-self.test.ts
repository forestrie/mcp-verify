/**
 * `verifySelf` over the frozen real bundle (plan-2609-02 steps 2.4/2.5).
 *
 * `test/fixtures/self-bundle/PROVENANCE.md` records what was verified at
 * capture with the `forestrie` CLI: `--payload statement.cose` PASSES,
 * `--payload provenance.json` reports `signature_invalid`, and
 * `--genesis genesis.cbor` reports `delegation_invalid` (the publications
 * log is a grandchild of the forest root; nothing walks the grant chain
 * that far yet). This file asserts the same facts through `verifySelf`.
 */
import { describe, expect, it } from "vitest";
import { verifySelf, type SelfBundle } from "../../src/core/index.js";
import { GOLDEN_MANIFEST, fromHex } from "../../src/node/fixtures.js";
import { readSelfBundle } from "./self-bundle.js";

function flip(bytes: Uint8Array, at: number): Uint8Array {
  const out = bytes.slice();
  const i = at < 0 ? out.length + at : at;
  out[i] = (out[i] ?? 0) ^ 0xff;
  return out;
}

describe("verifySelf — the default root", () => {
  it("passes at known-log-key, the default", async () => {
    const bundle = readSelfBundle();
    const r = await verifySelf(bundle);
    expect(r.ok).toBe(true);
    expect(r.root).toBe("known-log-key");
    expect(r.self.statementSignature).toBe("ok");
    expect(r.self.payloadMatchesProvenance).toBe(true);
    expect(r.self.provenance).toEqual({
      name: "@forestrie/mcp-verify",
      version: "0.2.0",
      gitCommit: "62c31ad38032b775fd6bdb06055a36f2a27503ef",
      builtAt: "2026-09-12T18:32:33.810Z",
    });
  });

  it("names the un-walked grant chain — known-log-key is trusted as shipped", async () => {
    const r = await verifySelf(readSelfBundle());
    expect(r.diagnostics.map((d) => d.code)).toContain(
      "self_chain_not_walked",
    );
  });

  it("attribution says who signed, not just that the leaf commits bytes", async () => {
    const r = await verifySelf(readSelfBundle());
    expect(r.questions.attribution.status).toBe("ok");
    expect(r.questions.attribution.note).toContain("log-key.xy.b64");
  });

  it("never a bare pass: every question carries a note", async () => {
    const r = await verifySelf(readSelfBundle());
    for (const q of [
      "sealing",
      "split-view",
      "append-authority",
      "attribution",
    ] as const) {
      expect(r.questions[q].note.length).toBeGreaterThan(10);
    }
  });
});

describe("verifySelf — genesis is not the default, and reports why", () => {
  /**
   * Verified at capture (PROVENANCE.md): `forestrie verify --genesis
   * genesis.cbor ...` on this exact receipt reports `delegation_invalid`.
   * The genesis root vouches for the forest root log only; the publications
   * log is a grandchild (root → auth log → publications log) and no offline
   * walk reaches that far yet. This is why `verifySelf`'s default is
   * known-log-key, not genesis — docs/self-registration.md, "The grant
   * chain: recorded, not walked".
   */
  it("reports delegation_invalid under an explicit genesis root", async () => {
    const bundle = readSelfBundle();
    const r = await verifySelf(bundle, {
      root: { root: "genesis", genesis: bundle.genesis },
    });
    expect(r.ok).toBe(false);
    expect(r.stage).toBe("signature");
    expect(r.reason).toBe("delegation_invalid");
    expect(r.diagnostics.map((d) => d.code)).toContain(
      "self_chain_not_walked",
    );
  });
});

describe("verifySelf — tamper matrix", () => {
  it("a flipped byte in provenance.json: payloadMatchesProvenance false, FAIL", async () => {
    const bundle = readSelfBundle();
    // Flip a byte inside the gitCommit hex value so the JSON still parses —
    // the point of this case is a payload MISMATCH, not a parse failure.
    const tampered = flip(bundle.provenanceJson, 100);
    const r = await verifySelf({ ...bundle, provenanceJson: tampered });
    expect(r.self.payloadMatchesProvenance).toBe(false);
    expect(r.ok).toBe(false);
    // The receipt + statement pair is untouched, so (a) still mechanically
    // passes; it is the self-check in (b) that fails this closed.
    expect(r.self.statementSignature).toBe("ok");
    expect(r.questions.attribution.status).toBe("failed");
  });

  it("a flipped byte in statement.cose: FAIL at signature", async () => {
    const bundle = readSelfBundle();
    const tampered = flip(bundle.statementCose, -1);
    const r = await verifySelf({ ...bundle, statementCose: tampered });
    expect(r.ok).toBe(false);
    expect(r.stage).toBe("signature");
    expect(r.reason).toBe("signature_invalid");
  });

  it("a flipped byte in receipt.cbor's signature: FAIL at signature", async () => {
    const bundle = readSelfBundle();
    // The COSE signature is the final element of the Sign1 array, so the
    // final byte of a canonically-encoded receipt is inside it — the same
    // convention test/core/tamper.ts uses for the golden receipt.
    const tampered = flip(bundle.receipt, -1);
    const r = await verifySelf({ ...bundle, receipt: tampered });
    expect(r.ok).toBe(false);
    expect(r.stage).toBe("signature");
    expect(r.reason).toBe("signature_invalid");
  });

  it("a wrong (but validly-encoded) log-key.xy.b64: FAIL", async () => {
    const bundle = readSelfBundle();
    // A different real P-256 point — the golden grant-receipt fixture's log
    // key — rather than a byte flip that might land off-curve and fail for
    // the wrong reason (bad key material, not a wrong key).
    const wrongKey = fromHex(GOLDEN_MANIFEST.grantDataHex);
    const r = await verifySelf({ ...bundle, logKeyXy: wrongKey });
    expect(r.ok).toBe(false);
    expect(r.self.statementSignature).toBe("failed");
  });

  it("a bundle-shaped input with garbage bytes fails closed, never throws", async () => {
    const bundle: SelfBundle = {
      ...readSelfBundle(),
      receipt: new Uint8Array([1, 2, 3]),
    };
    const r = await verifySelf(bundle);
    expect(r.ok).toBe(false);
    expect(r.stage).toBe("parse");
  });
});

describe("verifySelf — an explicit known-accumulator root", () => {
  /**
   * The bundle ships no accumulator snapshot (docs/self-registration.md),
   * so this is necessarily a caller-supplied one. A snapshot that does not
   * hold the receipt's peak must fail split-view, exactly like every other
   * known-accumulator run in test/core/root-table.test.ts.
   */
  it("a foreign snapshot fails split-view rather than passing silently", async () => {
    const bundle = readSelfBundle();
    const { encodeKnownAccumulator } =
      await import("@forestrie/receipt-verify");
    const foreign = encodeKnownAccumulator({
      version: 1,
      chainId: 84532n,
      univocity: new Uint8Array(20).fill(0xab),
      logId: new Uint8Array(32).fill(0xcd),
      size: 1n,
      accumulator: [new Uint8Array(32).fill(0x11)],
      blockNumber: 1n,
      blockHash: new Uint8Array(32).fill(0xef),
    });
    const r = await verifySelf(bundle, {
      root: { root: "known-accumulator", accumulator: foreign },
    });
    expect(r.ok).toBe(false);
    expect(r.questions["split-view"].status).toBe("failed");
    // This root has its own accumulator; the un-walked-chain note is about
    // known-log-key and genesis only.
    expect(r.diagnostics.map((d) => d.code)).not.toContain(
      "self_chain_not_walked",
    );
  });
});
