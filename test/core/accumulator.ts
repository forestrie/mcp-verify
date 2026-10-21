/**
 * Building a known-accumulator snapshot for the golden grant receipt.
 *
 * **Read this before trusting what the accumulator-root tests prove.**
 *
 * The golden fixture set has no accumulator artifact — it is a genesis +
 * receipt pair. So the snapshot here is *derived from the receipt's own
 * recomputed peak*, exactly as `@forestrie/receipt-verify`'s own
 * `test/known-accumulator.test.ts` does (`recomputeFixturePeak`, then
 * `accumulator: [peak]`). That makes the CLEAN case a **self-consistency
 * check, not an independent snapshot**: it proves the plumbing is wired to
 * the right peak, not that the peak is the one Base Sepolia holds.
 *
 * What it still proves, and what the separation claim actually rests on,
 * is the TAMPERED cases. The snapshot is built once from the clean receipt
 * and then held fixed while the receipt is tampered. A flipped inclusion-path
 * byte changes the recomputed peak, which is then no longer in the accumulator
 * — and that failure is reported distinctly from a flipped signature byte,
 * which at the genesis root it is not. That is the whole claim, and a
 * derived-but-fixed accumulator exercises it honestly.
 *
 * An independent snapshot would be strictly better and belongs in the shared
 * conformance vectors planned for `forestrie/protocol`.
 * Until those exist, this is the honest version, said out loud.
 *
 * The peak recompute itself lives in `src/core/peak.ts` — the package needs it
 * anyway, to report WHICH accumulator peak a receipt matched and to run the
 * demo's second root.
 */
import {
  encodeKnownAccumulator,
  entryIdHexToIdtimestampBe8,
  grantCommitmentHashFromGrant,
  type KnownAccumulator,
} from "@forestrie/receipt-verify";
import { indexHeight, peakMMRIndexes } from "@forestrie/merklelog";
import { parseReceipt } from "@forestrie/receipt-verify";
import { recomputeReceiptPeak } from "../../src/core/index.js";
import { decodeGrantPayload } from "@forestrie/encoding";

/** The receipt's peak, recomputed from leaf + inclusion path. */
export async function recomputePeak(input: {
  receipt: Uint8Array;
  committedGrant: Uint8Array;
  entryId: string;
}): Promise<{ peak: Uint8Array; leafIndex: bigint }> {
  const grant = decodeGrantPayload(input.committedGrant);
  return recomputeReceiptPeak({
    receiptCbor: input.receipt,
    idtimestampBe8: entryIdHexToIdtimestampBe8(input.entryId),
    inner: await grantCommitmentHashFromGrant(grant),
  });
}

/**
 * A snapshot artifact holding one peak. The binding fields (chainId,
 * univocity address, logId, block) are placeholders: nothing in this package
 * reads them for a verdict — `assertSnapshotBinding` is the caller's job and
 * this package never claims the snapshot came from a chain read. They are
 * present because `encodeKnownAccumulator` requires the shape.
 */
export function snapshotOverPeaks(
  peaks: Uint8Array[],
  size: bigint,
): Uint8Array {
  const snapshot: KnownAccumulator = {
    version: 1,
    chainId: 84532n,
    univocity: new Uint8Array(20).fill(0xab),
    logId: new Uint8Array(32).fill(0xcd),
    size,
    accumulator: peaks,
    blockNumber: 1_234_567n,
    blockHash: new Uint8Array(32).fill(0xef),
  };
  return encodeKnownAccumulator(snapshot);
}

/**
 * The MMR node the receipt's inclusion walk reaches: the peak the receipt
 * commits to. Mirrors the walk in the MMR proof arithmetic: at each step the
 * node is a right child when the next index is taller, else a left child.
 */
export function inclusionWalkNode(receipt: Uint8Array): bigint {
  const { proof } = parseReceipt(receipt);
  let i = proof.leafIndex ?? proof.mmrIndex ?? 0n;
  let g = indexHeight(i);
  for (let step = 0; step < proof.path.length; step++) {
    i = indexHeight(i + 1n) > g ? i + 1n : i + (2n << BigInt(g));
    g++;
  }
  return i;
}

/**
 * A valid accumulator for the receipt: size = (walk node) + 1, so the walk's
 * node is always a peak of that size; the recomputed peak sits at that peak's
 * position and every other position holds a distinct dummy value. Optionally
 * place the real peak at a different position (a mis-ordered accumulator).
 */
export function validAccumulatorFor(
  receipt: Uint8Array,
  peak: Uint8Array,
  opts: { position?: number } = {},
): { size: bigint; peaks: Uint8Array[]; position: number } {
  const node = inclusionWalkNode(receipt);
  const size = node + 1n;
  const indexes = peakMMRIndexes(size - 1n);
  const position = indexes.findIndex((x) => x === node);
  if (position < 0) throw new Error("walk node is not a peak of its own size");
  const at = opts.position ?? position;
  const peaks: Uint8Array[] = indexes.map((_, k) =>
    new Uint8Array(32).fill(0x20 + k),
  );
  peaks[at] = peak;
  return { size, peaks, position };
}

/**
 * The snapshot the root-table tests hold fixed across every tamper variant.
 * Built once from the CLEAN golden receipt as a VALID accumulator (see
 * {@link validAccumulatorFor}); the size covers the leaf.
 */
export async function goldenAccumulatorSnapshot(input: {
  receipt: Uint8Array;
  committedGrant: Uint8Array;
  entryId: string;
}): Promise<Uint8Array> {
  const { peak } = await recomputePeak(input);
  const { size, peaks } = validAccumulatorFor(input.receipt, peak);
  return snapshotOverPeaks(peaks, size);
}
