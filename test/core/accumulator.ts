/**
 * Building a known-accumulator snapshot for the golden grant receipt.
 *
 * **Read this before trusting what the accumulator-rung tests prove.**
 *
 * The golden fixture set has no accumulator artifact — it is a genesis +
 * receipt pair. So the snapshot here is *derived from the receipt's own
 * recomputed peak*, exactly as `@forestrie/receipt-verify`'s own
 * `test/known-accumulator.test.ts` does (`recomputeFixturePeak`, then
 * `accumulator: [peak]`). That makes the CLEAN case a **self-consistency
 * check, not an independent snapshot**: it proves the plumbing is wired to
 * the right peak, not that the peak is the one Base Sepolia holds.
 *
 * What it still proves, and what the D3 separation claim actually rests on,
 * is the TAMPERED cases. The snapshot is built once from the clean receipt
 * and then held fixed while the receipt is tampered. A flipped inclusion-path
 * byte changes the recomputed peak, which is then no longer in the accumulator
 * — and that failure is reported distinctly from a flipped signature byte,
 * which at the genesis rung it is not. That is the whole claim, and a
 * derived-but-fixed accumulator exercises it honestly.
 *
 * An independent snapshot would be strictly better and belongs in the shared
 * conformance vectors the parent plan schedules for `forestrie/protocol`.
 * Until those exist, this is the honest version, said out loud.
 *
 * The peak recompute itself lives in `src/core/peak.ts` — the package needs it
 * anyway, to report WHICH accumulator peak a receipt matched and to run the
 * demo's second rung.
 */
import {
  encodeKnownAccumulator,
  entryIdHexToIdtimestampBe8,
  grantCommitmentHashFromGrant,
  type KnownAccumulator,
} from "@forestrie/receipt-verify";
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
 * The snapshot the rung-table tests hold fixed across every tamper variant.
 * Built once from the CLEAN golden receipt; `size` is one past the leaf so
 * the receipt is covered rather than newer-than-snapshot.
 */
export async function goldenAccumulatorSnapshot(input: {
  receipt: Uint8Array;
  committedGrant: Uint8Array;
  entryId: string;
}): Promise<Uint8Array> {
  const { peak, leafIndex } = await recomputePeak(input);
  return snapshotOverPeaks([peak], leafIndex + 1n);
}
