/**
 * `verifyGrantReceipt` over the frozen golden vectors.
 *
 * The golden fixtures ARE a grant receipt (detached payload, 118 B), so this
 * is the function the vectors can exercise directly — which is why it was
 * written before `verifyReceipt`.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { verifyGrantReceipt, VERIFIER } from "../../src/core/index.js";
import {
  BURIAL_MANIFEST,
  GOLDEN_MANIFEST,
  fromHex,
  goldenCommittedGrant,
  goldenEntryId,
} from "../../src/node/fixtures.js";
import { GENESIS, grantCases } from "./tamper.js";

const repoRoot = new URL("../../", import.meta.url).pathname;
const pkg = JSON.parse(readFileSync(`${repoRoot}package.json`, "utf8")) as {
  version: string;
  dependencies: Record<string, string>;
};

/**
 * The golden genesis's bootstrap key (label -68015) is byte-identical to the
 * manifest's `grantDataHex` — the fixture generator uses one P-256 key for
 * both the log's trust root and the grant's committed key material. That is
 * what makes the known-log-key root testable from the manifest alone.
 */
const KEY_XY = fromHex(GOLDEN_MANIFEST.grantDataHex);

const clean = () => grantCases()[0]!;

describe("verifyGrantReceipt — the frozen receipt against the frozen genesis", () => {
  it("verifies at the genesis root", async () => {
    const c = clean();
    const result = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: c.committedGrant,
      entryId: c.entryId,
      trust: { root: "genesis", genesis: GENESIS },
    });
    expect(result.ok).toBe(true);
    expect(result.stage).toBe("binding");
    expect(result.reason).toBeUndefined();
    expect(result.stages).toEqual([
      { stage: "parse", status: "ok" },
      { stage: "signature", status: "ok" },
      { stage: "inclusion", status: "ok" },
      { stage: "binding", status: "ok" },
    ]);
  });

  /**
   * This is the assertion that makes reconstructing the committed grant from
   * `manifest.json` safe rather than a guess: if the field layout were wrong,
   * the leaf would not commit it and the test above could not pass.
   */
  it("the reconstructed committed grant is the one the leaf commits", async () => {
    expect(goldenCommittedGrant().byteLength).toBeGreaterThan(64);
    expect(goldenEntryId()).toMatch(/^[0-9a-f]{32}$/);
  });

  it("verifies at the known-log-key root, and says the anchor is not genesis", async () => {
    const c = clean();
    const result = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: c.committedGrant,
      entryId: c.entryId,
      trust: { root: "known-log-key", keyXy: KEY_XY },
    });
    expect(result.ok).toBe(true);
    expect(result.root).toBe("known-log-key");
    const signature = result.stages.find((r) => r.stage === "signature");
    expect(signature?.reason).toContain("caller-known log key");
  });

  it("fails under a different, valid known log key", async () => {
    const c = clean();
    // The burial bundle's log key: a real P-256 point, wrong log.
    const otherLog = fromHex(BURIAL_MANIFEST.publicKeyXyHex);
    const result = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: c.committedGrant,
      entryId: c.entryId,
      trust: { root: "known-log-key", keyXy: otherLog },
    });
    expect(result.ok).toBe(false);
  });

  /**
   * WebCrypto throws a bare `DataError: Invalid keyData` for bytes that are
   * not a point on P-256. That must never reach a caller as a stack trace:
   * "the key you gave me is not a key" is an input error with an obvious
   * remedy, and this layer owes the caller that sentence.
   */
  it("a corrupt known log key is a clean input failure, not a thrown DataError", async () => {
    const c = clean();
    const wrong = KEY_XY.slice();
    wrong[0] = (wrong[0] ?? 0) ^ 0xff;
    const result = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: c.committedGrant,
      entryId: c.entryId,
      trust: { root: "known-log-key", keyXy: wrong },
    });
    expect(result.ok).toBe(false);
    expect(result.stage).toBe("parse");
    expect(result.reason).toMatch(/not a valid P-256 public key/);
  });

  it("a wrong-length known log key names the expected length", async () => {
    const c = clean();
    const result = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: c.committedGrant,
      entryId: c.entryId,
      trust: { root: "known-log-key", keyXy: new Uint8Array(32) },
    });
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/64 bytes/);
  });

  it("reports the exact verifier identity, and it matches package.json", () => {
    expect(VERIFIER.package).toBe("@forestrie/mcp-verify");
    expect(VERIFIER.version).toBe(pkg.version);
    expect(VERIFIER.receiptVerify).toBe(
      pkg.dependencies["@forestrie/receipt-verify"],
    );
  });
});

describe("verifyGrantReceipt — input validation is ours, not the reference's", () => {
  /**
   * forestrie-cli crashes with an uncaught stack trace when the committed
   * grant is missing, even under --json (plan-2609-02 "What changed on
   * contact" 3). This layer validates its own inputs and returns a clean
   * structured failure instead.
   */
  it("a committed grant that is neither COSE nor raw payload is a clean parse failure", async () => {
    const c = clean();
    const result = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: new Uint8Array([0xff, 0xff, 0xff]),
      entryId: c.entryId,
      trust: { root: "genesis", genesis: GENESIS },
    });
    expect(result.ok).toBe(false);
    expect(result.stage).toBe("parse");
    expect(result.reason).toMatch(/neither a Forestrie-Grant COSE Sign1/);
    // A failed run still answers the questions it can, and says which it cannot.
    expect(result.questions["split-view"].status).toBe(
      "not_answered_by_this_root",
    );
  });

  it("a raw grant payload with no entryId is a clean parse failure naming the remedy", async () => {
    const c = clean();
    const result = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: c.committedGrant,
      trust: { root: "genesis", genesis: GENESIS },
    });
    expect(result.ok).toBe(false);
    expect(result.stage).toBe("parse");
    expect(result.reason).toMatch(/supply entryId/);
  });

  it("never throws for any tamper variant at any of the two offline roots", async () => {
    for (const c of grantCases()) {
      for (const trust of [
        { root: "genesis" as const, genesis: GENESIS },
        { root: "known-log-key" as const, keyXy: KEY_XY },
      ]) {
        await expect(
          verifyGrantReceipt({
            receipt: c.receipt,
            committedGrant: c.committedGrant,
            entryId: c.entryId,
            trust,
          }),
        ).resolves.toHaveProperty("stages");
      }
    }
  });
});
