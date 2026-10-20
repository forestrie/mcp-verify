/**
 * Recomputing a receipt's MMR peak from leaf + inclusion path.
 *
 * This is the value everything at the accumulator roots turns on: it is what
 * gets compared against an accumulator you trust, and — because this
 * receipt's payload is detached — it is also what the COSE signature covers.
 * Which is exactly why the stages collapse at the signature roots: you cannot
 * check the signature without first computing this, and you cannot tell a bad
 * path from a bad signature when the only evidence is that the check failed.
 *
 * `@forestrie/merklelog` owns the MMR arithmetic and `@forestrie/receipt-verify`
 * owns the leaf commitment; this file owns neither. It exists because
 * receipt-verify does not re-export `calculateRoot`, and because
 * `verifyReceiptOfflineAgainstKnownAccumulator` answers "is the peak in this
 * accumulator" without saying WHICH peak matched — a number the anchor report
 * has to carry. Reimplementing either would be absurd in a package whose whole
 * argument is that it reimplements nothing.
 *
 * Browser-safe: the hasher below is WebCrypto, not `node:crypto`, so this file
 * stays inside the `platform: "browser"` bundle the purity gate builds.
 * (merklelog's own `createSyncHasher` is node-only, which is why it is not
 * used here.)
 */
import { calculateRoot, type Hasher } from "@forestrie/merklelog";
import { parseReceipt, univocityLeafHash } from "@forestrie/receipt-verify";

/**
 * A `Hasher` over WebCrypto. merklelog's interface is reset/update/digest, so
 * chunks accumulate until `digest()`; SHA-256 inputs here are two or three
 * 32-byte nodes, so the buffering is trivial.
 */
class SubtleHasher implements Hasher {
  #chunks: Uint8Array[] = [];

  reset(): void {
    this.#chunks = [];
  }

  update(data: Uint8Array): void {
    this.#chunks.push(data);
  }

  async digest(): Promise<Uint8Array> {
    let total = 0;
    for (const c of this.#chunks) total += c.length;
    const joined = new Uint8Array(total);
    let at = 0;
    for (const c of this.#chunks) {
      joined.set(c, at);
      at += c.length;
    }
    return new Uint8Array(await crypto.subtle.digest("SHA-256", joined));
  }
}

export type RecomputedPeak = {
  peak: Uint8Array;
  /** The leaf's MMR index, which is also what bounds snapshot coverage. */
  leafIndex: bigint;
};

/**
 * Recompute the peak the receipt's inclusion path commits to.
 *
 * `inner` is the leaf ContentHash — `SHA-256(payload)` for a payload receipt,
 * the grant commitment hash for a grant receipt. The leaf itself is
 * `SHA-256(idtimestamp ‖ inner)`, which is what binds the bytes to the moment
 * they were sequenced.
 *
 * The peak is always recomputed from leaf + path; an attached peak is only
 * checked for equality, never used in its place.
 *
 * @throws if the receipt does not parse, or an attached peak disagrees with
 * the recomputation — callers that need a verdict rather
 * than an exception should let `verifyReceiptOfflineAgainstKnownAccumulator`
 * produce it, which is what the verify paths do.
 */
export async function recomputeReceiptPeak(input: {
  receiptCbor: Uint8Array;
  idtimestampBe8: Uint8Array;
  inner: Uint8Array;
}): Promise<RecomputedPeak> {
  const parsed = parseReceipt(input.receiptCbor);
  const leafIndex =
    parsed.proof.leafIndex !== undefined
      ? parsed.proof.leafIndex
      : (parsed.proof.mmrIndex ?? 0n);
  const leafHash = await univocityLeafHash(input.idtimestampBe8, input.inner);
  const peak = await calculateRoot(
    new SubtleHasher(),
    leafHash,
    parsed.proof,
    leafIndex,
  );
  // A peak attached to the receipt is never trusted over the recomputation
  // (receipt-verify 3.2.0 closed that hole); if one is attached it must equal
  // what leaf + path commit to.
  if (parsed.explicitPeak !== null && !bytesEqual(parsed.explicitPeak, peak)) {
    throw new Error(
      "attached peak does not match the peak recomputed from leaf and inclusion path",
    );
  }
  return { peak, leafIndex };
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let x = 0;
  for (let i = 0; i < a.length; i++) x |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return x === 0;
}
