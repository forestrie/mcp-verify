/**
 * `demo` — two trust roots over the bundled fixtures.
 *
 * The point of the transcript is not that a receipt verifies. It is that the
 * SAME BYTES answer different questions under different trust roots, and
 * that under a signature root four structurally different tampers are one
 * indistinguishable answer. A demo that only showed a pass would be showing the least
 * interesting thing this package does.
 *
 * Everything printed here goes to the caller's writer, never to `console`
 * directly, so `cli.ts` can guarantee that stdio mode writes nothing to
 * stdout but MCP frames.
 */
import {
  recomputeReceiptPeak,
  summarize,
  verifyGrantReceipt,
  type TrustRoot,
  type VerifyResult,
} from "../core/index.js";
import {
  encodeKnownAccumulator,
  entryIdHexToIdtimestampBe8,
  grantCommitmentHashFromGrant,
} from "@forestrie/receipt-verify";
import { decodeGrantPayload } from "@forestrie/encoding";
import {
  GOLDEN_MANIFEST,
  fromHex,
  goldenCommittedGrant,
  goldenEntryId,
  readFixture,
} from "./fixtures.js";

export type Writer = (line: string) => void;

const GENESIS = () => readFixture("golden/grant-genesis.cbor");
const RECEIPT = () => readFixture("golden/grant-receipt.cbor");

/** Flip the last byte: the COSE signature is the final element of the Sign1
 *  array, so this lands inside it. */
function tamperSignature(receipt: Uint8Array): Uint8Array {
  const out = receipt.slice();
  out[out.length - 1] = (out[out.length - 1] ?? 0) ^ 0xff;
  return out;
}

/** Alter the idtimestamp half of the entry id — a different tamper entirely,
 *  and the one whose indistinguishability is the point. */
function tamperEntryId(entryId: string): string {
  const idt = fromHex(GOLDEN_MANIFEST.idtimestampBe8Hex);
  idt[7] = (idt[7] ?? 0) ^ 0x01;
  const hex = Array.from(idt, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex}${entryId.slice(16)}`;
}

function printResult(write: Writer, label: string, r: VerifyResult): void {
  write(`  ${label}`);
  write(`    ${summarize("verify-grant", r)}`);
  for (const row of r.stages) {
    write(
      `      ${row.stage.padEnd(10)} ${row.status.padEnd(8)}${
        row.reason !== undefined ? ` — ${row.reason}` : ""
      }`,
    );
  }
  if (r.anchor !== undefined) {
    write(
      `      anchor     ${
        r.anchor.anchored ? "ok      " : "failed  "
      } — peak ${
        r.anchor.matchedPeak === null
          ? "not found"
          : `${r.anchor.matchedPeak + 1}/${r.anchor.peakCount}`
      } at anchored size ${r.anchor.anchoredSize}`,
    );
  }
  for (const d of r.diagnostics) {
    write(`      ! ${d.code}`);
  }
  write("");
}

/**
 * Build a known-accumulator snapshot from the clean receipt's own recomputed
 * peak, so the demo can run an accumulator root with no network and no fixture
 * that does not ship.
 *
 * SAY THIS OUT LOUD IN THE TRANSCRIPT, because it is the difference between a
 * demonstration and a claim: a self-derived accumulator proves the SEPARATION
 * (tamper the path, the peak moves, the anchor rejects it) but it does not
 * prove the peak is the one the chain holds. A real run supplies a snapshot
 * from `forestrie fetch-accumulator` or any independent chain reader.
 */
async function deriveSnapshot(): Promise<Uint8Array> {
  const { peak, leafIndex } = await recomputeReceiptPeak({
    receiptCbor: RECEIPT(),
    idtimestampBe8: entryIdHexToIdtimestampBe8(goldenEntryId()),
    inner: await grantCommitmentHashFromGrant(
      decodeGrantPayload(goldenCommittedGrant()),
    ),
  });
  return encodeKnownAccumulator({
    version: 1,
    chainId: 84532n,
    // Binding fields are placeholders: nothing here reads them for a verdict,
    // and this snapshot is explicitly NOT a chain read. `assertSnapshotBinding`
    // is the caller's job with a real one.
    univocity: new Uint8Array(20).fill(0xab),
    logId: new Uint8Array(32).fill(0xcd),
    size: leafIndex + 1n,
    accumulator: [peak],
    blockNumber: 1_234_567n,
    blockHash: new Uint8Array(32).fill(0xef),
  });
}

export async function runDemo(write: Writer): Promise<number> {
  const genesis = GENESIS();
  const receipt = RECEIPT();
  const committedGrant = goldenCommittedGrant();
  const entryId = goldenEntryId();

  write("");
  write("@forestrie/mcp-verify — two trust roots over the bundled fixtures");
  write("");
  write("No network. No account. No key. No backend. These 118 bytes of");
  write("receipt and 160 bytes of genesis ship inside the package.");
  write("");

  const at = (
    trust: TrustRoot,
    over: Partial<{
      receipt: Uint8Array;
      entryId: string;
    }> = {},
  ) =>
    verifyGrantReceipt({
      receipt: over.receipt ?? receipt,
      committedGrant,
      entryId: over.entryId ?? entryId,
      trust,
    });

  const genesisRoot: TrustRoot = { root: "genesis", genesis };

  write("── Trust root: genesis ───────────────────────────────────────────");
  write("The log's own genesis document is the trust root.");
  write("");
  printResult(write, "the frozen receipt, untouched:", await at(genesisRoot));
  printResult(
    write,
    "the same receipt, one SIGNATURE byte flipped:",
    await at(genesisRoot, { receipt: tamperSignature(receipt) }),
  );
  printResult(
    write,
    "the same receipt, a wrong IDTIMESTAMP:",
    await at(genesisRoot, { entryId: tamperEntryId(entryId) }),
  );

  write("Look at those last two. Different tampers. Same answer:");
  write("stage=signature reason=signature_invalid. That is not sloppiness —");
  write(
    "this receipt has a DETACHED payload, so its signature covers the MMR",
  );
  write("peak, a value only knowable after recomputing it from leaf + path.");
  write("With no independent accumulator, 'the path is wrong' and 'the");
  write("signature is wrong' are the same observation. The tool says so in");
  write("the detached_payload_stage_collapse diagnostic rather than letting");
  write("you assume it distinguished them.");
  write("");

  const snapshot = await deriveSnapshot();
  const accumulatorRoot: TrustRoot = {
    root: "known-accumulator",
    accumulator: snapshot,
  };

  write("── Trust root: known-accumulator ─────────────────────────────────");
  write("Now the trust root is an accumulator snapshot the CALLER holds.");
  write("");
  write("NOTE: this demo derives the snapshot from the clean receipt's own");
  write("recomputed peak, because no chain-read snapshot ships with the");
  write(
    "fixtures. That makes the PASS below a self-consistency check, not an",
  );
  write("independent one. What it does prove is the separation: the snapshot");
  write("is then held FIXED while the receipt is tampered. In a real run you");
  write("supply a snapshot from `forestrie fetch-accumulator`, or any");
  write("independent reader of the univocity contract.");
  write("");
  printResult(
    write,
    "the frozen receipt, untouched:",
    await at(accumulatorRoot),
  );
  printResult(
    write,
    "the same receipt, a wrong IDTIMESTAMP:",
    await at(accumulatorRoot, { entryId: tamperEntryId(entryId) }),
  );

  write("Same bytes. More questions answered. split-view went from");
  write("'not answered at this root' to a real verdict, and the idtimestamp");
  write("tamper is now peak_not_in_known_accumulator instead of an");
  write("indistinguishable signature failure.");
  write("");
  write("One more thing worth knowing, and this package will not hide it:");
  write("");
  printResult(
    write,
    "one SIGNATURE byte flipped, under the accumulator root:",
    await at(accumulatorRoot, { receipt: tamperSignature(receipt) }),
  );
  write("It PASSES. This root evaluates no signature at all. The recomputed");
  write("peak comes from leaf + inclusion path, neither of which a signature");
  write("flip touches — and a peak that matches a consistency-gated on-chain");
  write("accumulator IS the proof, because univocity refuses to publish a");
  write("checkpoint whose signature does not verify. The 'sealing' answer");
  write("says exactly that: ok, implied by the anchor.");
  write("");
  write("That is the point. Never a bare 'valid' — always which root, and");
  write("which questions that root can and cannot answer.");
  write("");
  write("docs/trust-roots.md has the full table.");
  write("");
  return 0;
}
