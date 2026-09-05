/**
 * The checkpoint-chain rung, over the FOR-368 burial bundle.
 *
 * What this rung does: fold the retained `.sth` chain from its boundary base,
 * verifying each link's signature over the accumulator its own consistency
 * proof derives, then look for the receipt's recomputed peak in ANY
 * authenticated link. A match at any link is proof, because each later link's
 * signed proof commits the earlier accumulator forward — which is exactly why
 * burial never turns an honest receipt tamper-shaped.
 *
 * **Coverage limit, stated plainly.** The burial manifest records the leaf
 * HASH, not the leaf's preimage (`idtimestamp` + inner ContentHash), and the
 * public API only takes the preimage. So there is no positive
 * receipt-matches-chain case available from the shipped fixtures. What is
 * covered here is everything else on the path: the four-link fold, every
 * signature, the folded accumulator against the manifest's recorded value,
 * the peak-not-found verdict, and the missing-trust-root refusal. A positive
 * case needs a fixture that ships the leaf preimage alongside the chain, and
 * belongs in the shared conformance vectors the parent plan schedules for
 * `forestrie/protocol`.
 */
import { describe, expect, it } from "vitest";
import {
  importEs256PublicKeyFromGrantDataXy64,
  resolveDelegatedVerifyKey,
  verifyCheckpointChain,
} from "@forestrie/receipt-verify";
import { verifyCoseSign1WithParsedKey } from "@forestrie/encoding";
import { verifyGrantReceipt } from "../../src/core/index.js";
import {
  BURIAL_MANIFEST,
  GOLDEN_MANIFEST,
  fromHex,
  readFixture,
} from "../../src/node/fixtures.js";
import { GENESIS, grantCases } from "./tamper.js";

const CHAIN = BURIAL_MANIFEST.checkpointFiles.map((f) =>
  readFixture(`golden/burial/${f}`),
);
const CHAIN_KEY_XY = fromHex(BURIAL_MANIFEST.publicKeyXyHex);
const GOLDEN_KEY_XY = fromHex(GOLDEN_MANIFEST.grantDataHex);

const hex = (b: Uint8Array) =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

describe("the retained checkpoint chain folds and authenticates", () => {
  /**
   * Not a test of this package's code so much as a test that the fixture and
   * the library still agree — but it is the precondition for everything the
   * rung claims, so it fails loudly here rather than confusingly downstream.
   */
  it("all four links verify and fold to the manifest's final accumulator", async () => {
    const rootKey = await importEs256PublicKeyFromGrantDataXy64(CHAIN_KEY_XY);
    const chain = await verifyCheckpointChain({
      checkpoints: CHAIN,
      verifySignature: async (cp, detachedPayload) => {
        const res = await resolveDelegatedVerifyKey(cp, [rootKey]);
        if (res.kind === "broken") return false;
        const candidates =
          res.kind === "resolved" ? [res.delegatedKey, rootKey] : [rootKey];
        for (const key of candidates) {
          if (
            await verifyCoseSign1WithParsedKey(cp, key, {
              logPrefix: "test",
              detachedPayload,
            })
          ) {
            return true;
          }
        }
        return false;
      },
    });
    expect(chain.ok).toBe(true);
    if (!chain.ok) return;
    expect(chain.links).toHaveLength(4);
    expect(chain.links.every((l) => l.signatureOk)).toBe(true);
    expect(chain.accumulator.map(hex)).toEqual(
      BURIAL_MANIFEST.finalAccumulatorHex,
    );
    // The buried peak is link 0's accumulator — the peak the live state no
    // longer holds, and the reason this rung exists.
    expect(chain.links[0]?.accumulator.map(hex)).toContain(
      BURIAL_MANIFEST.buriedPeakHex,
    );
  });
});

describe("verifyGrantReceipt at the checkpoint-chain rung", () => {
  it("reports peak_not_in_checkpoint_chain for a receipt from a different log", async () => {
    const c = grantCases()[0]!;
    const r = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: c.committedGrant,
      entryId: c.entryId,
      trust: {
        rung: "checkpoint-chain",
        checkpoints: CHAIN,
        keyXy: CHAIN_KEY_XY,
      },
    });
    expect(r.ok).toBe(false);
    // Renamed from the library's snapshot vocabulary: the caller supplied a
    // chain, so "refresh the accumulator" would be the wrong remedy.
    expect(r.reason).toBe("peak_not_in_checkpoint_chain");
    expect(r.anchor?.anchored).toBe(false);
    expect(r.anchor?.linkCount).toBe(4);
    expect(r.questions["split-view"].status).toBe("failed");
  });

  it("roots the chain in genesis as well as in a raw key", async () => {
    const c = grantCases()[0]!;
    const r = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: c.committedGrant,
      entryId: c.entryId,
      trust: {
        rung: "checkpoint-chain",
        checkpoints: CHAIN,
        keyXy: CHAIN_KEY_XY,
        genesis: GENESIS,
      },
    });
    // Extra roots are additive: the chain still folds under the right one.
    expect(r.anchor?.linkCount).toBe(4);
  });

  it("refuses cleanly when no trust root is supplied", async () => {
    const c = grantCases()[0]!;
    const r = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: c.committedGrant,
      entryId: c.entryId,
      trust: { rung: "checkpoint-chain", checkpoints: CHAIN },
    });
    expect(r.ok).toBe(false);
    expect(r.stage).toBe("parse");
    expect(r.reason).toMatch(/needs an ES256 trust root/);
  });

  it("refuses cleanly when the chain does not verify under the given root", async () => {
    const c = grantCases()[0]!;
    const r = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: c.committedGrant,
      entryId: c.entryId,
      // The golden log's key, against the burial log's chain.
      trust: {
        rung: "checkpoint-chain",
        checkpoints: CHAIN,
        keyXy: GOLDEN_KEY_XY,
      },
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/checkpoint chain did not verify/);
  });
});
