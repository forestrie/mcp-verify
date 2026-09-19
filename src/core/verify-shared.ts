/**
 * The parts of a verify run that do not depend on which receipt kind is being
 * verified: root dispatch for the two accumulator roots, result assembly, and
 * the one-line human summary.
 *
 * Everything here is pure over bytes. No `node:*`, no `fetch`, no `fs` — the
 * browser-safety gate bundles `src/core/index.ts` for `platform: "browser"`
 * and fails on any edge to a node builtin, so this file cannot acquire one
 * without CI going red.
 */
import {
  decodeKnownAccumulator,
  importEs256PublicKeyFromGrantDataXy64,
  parseReceipt,
  resolveDelegatedVerifyKey,
  verifyCheckpointChain,
  verifyReceiptOfflineAgainstKnownAccumulator,
  type CheckpointChainLink,
  type ReceiptVerifyResult,
} from "@forestrie/receipt-verify";
import { verifyCoseSign1WithParsedKey } from "@forestrie/encoding";
import { bytesEqual, recomputeReceiptPeak } from "./peak.js";
import type { AnchorReport, Diagnostic, VerifyResult } from "./result.js";
import type { RootName, TrustRoot } from "./root.js";
import { rootAnswersSplitView } from "./root.js";
import {
  anchoredStageRows,
  knownKeyStageRows,
  stageRows,
  VERIFY_STAGES,
} from "./stages.js";
import {
  diagnosticsFor,
  trustQuestions,
  type ReceiptKind,
} from "./questions.js";
import { PACKAGE_VERSION, RECEIPT_VERIFY_VERSION } from "./version.js";

export class VerifyInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerifyInputError";
  }
}

/**
 * Import a caller-known log OWNER key from raw 64-byte P-256 x‖y.
 *
 * Wrapped because WebCrypto throws a bare `DataError: Invalid keyData` for
 * anything that is not a point on the curve, and a stack trace is the wrong
 * answer to "you gave me the wrong key". The value is the delegation-cert
 * ISSUER's key, not the sealer key: the label-1000 cert still resolves under
 * it, so the anchor survives sealer rotation.
 */
export async function importKnownLogKey(
  keyXy: Uint8Array,
): Promise<CryptoKey> {
  if (keyXy.length !== 64) {
    throw new VerifyInputError(
      `keyXy must be raw P-256 x‖y (64 bytes), got ${keyXy.length}`,
    );
  }
  try {
    return await importEs256PublicKeyFromGrantDataXy64(keyXy);
  } catch (err) {
    throw new VerifyInputError(
      `keyXy is not a valid P-256 public key: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
}

/**
 * Is the receipt's COSE payload detached?
 *
 * The condition that makes the stage collapse possible: a detached payload
 * means the signature covers the MMR peak, which is only knowable after
 * recomputing it from leaf + path. Returns `undefined` when the receipt does
 * not parse at all — there is then nothing to be detached.
 */
export function isDetachedPayload(receipt: Uint8Array): boolean | undefined {
  try {
    const parsed = parseReceipt(receipt);
    return parsed.coseSign1[2] === null;
  } catch {
    return undefined;
  }
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Which peak of a trusted accumulator the receipt matched.
 *
 * `verifyReceiptOfflineAgainstKnownAccumulator` answers yes/no, not which, so
 * the index comes from recomputing the peak ourselves and looking it up. Same
 * arithmetic, same library — see src/core/peak.ts for why that recompute is
 * not a reimplementation of anything.
 */
async function findMatchedPeak(
  input: {
    receiptCbor: Uint8Array;
    idtimestampBe8: Uint8Array;
    inner: Uint8Array;
  },
  accumulator: Uint8Array[],
): Promise<number | null> {
  let peak: Uint8Array;
  try {
    ({ peak } = await recomputeReceiptPeak(input));
  } catch {
    return null;
  }
  for (let i = 0; i < accumulator.length; i++) {
    const candidate = accumulator[i];
    if (candidate !== undefined && bytesEqual(peak, candidate)) return i;
  }
  return null;
}

export type AnchoredOutcome = {
  result: ReceiptVerifyResult;
  anchor: AnchorReport;
};

/**
 * The known-accumulator root.
 *
 * NOTE what this does NOT do: it checks no signature. That is deliberate and
 * it is the whole reason the root separates what genesis cannot. An anchored
 * peak match implies a valid publishing signature, because univocity refuses
 * to publish a checkpoint whose signature does not verify under the log's
 * live delegation — so the accumulator you trust IS the authority, and the
 * arithmetic that runs is pure inclusion + binding. A tampered inclusion path
 * therefore fails HERE with `peak_not_in_known_accumulator`, where at the
 * genesis root it was indistinguishable from a bad signature.
 *
 * This deliberately differs from `forestrie verify --known-accumulator`,
 * which runs the genesis/known-key offline verify FIRST and only then checks
 * the anchor, so its stage collapse survives into the accumulator check. See
 * docs/trust-roots.md.
 */
export async function verifyAtKnownAccumulator(input: {
  receiptCbor: Uint8Array;
  idtimestampBe8: Uint8Array;
  inner: Uint8Array;
  accumulatorBytes: Uint8Array;
}): Promise<AnchoredOutcome> {
  // A snapshot that does not decode is an input error, reported as a
  // structured `stage=parse` result like a bad `keyXy` or `genesis` —
  // not the library's bare throw, which used to reach the caller as an
  // unprefixed message while the other two roots' bad bytes arrived as
  // a result. "Your root bytes are wrong" always arrives the same way.
  let snapshot: ReturnType<typeof decodeKnownAccumulator>;
  try {
    snapshot = decodeKnownAccumulator(input.accumulatorBytes);
  } catch (err) {
    throw new VerifyInputError(
      `accumulator is not an encodeKnownAccumulator snapshot (${input.accumulatorBytes.length} bytes): ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  const result = await verifyReceiptOfflineAgainstKnownAccumulator({
    receiptCbor: input.receiptCbor,
    idtimestampBe8: input.idtimestampBe8,
    inner: input.inner,
    accumulator: snapshot.accumulator,
    size: snapshot.size,
  });
  const matchedPeak = result.ok
    ? await findMatchedPeak(
        {
          receiptCbor: input.receiptCbor,
          idtimestampBe8: input.idtimestampBe8,
          inner: input.inner,
        },
        snapshot.accumulator,
      )
    : null;
  const anchor: AnchorReport = {
    anchored: result.ok,
    anchoredSize: snapshot.size.toString(),
    peakCount: snapshot.accumulator.length,
    matchedPeak,
    blockNumber: snapshot.blockNumber.toString(),
    blockHash: `0x${bytesToHex(snapshot.blockHash)}`,
    univocity: `0x${bytesToHex(snapshot.univocity)}`,
    logId: `0x${bytesToHex(snapshot.logId)}`,
  };
  if (result.reason !== undefined) anchor.reason = result.reason;
  return { result, anchor };
}

/**
 * Signature trust for chain links, rooted in the caller's anchor: resolve
 * each checkpoint's label-1000 delegation cert under the root keys, then
 * verify the COSE signature over the FOLDED accumulator as detached payload.
 * The payload is computed by the fold, never read from the checkpoint — a
 * link only authenticates the accumulator its own proof derives (ADR-0046).
 */
function makeCheckpointSignatureVerifier(
  rootKeys: CryptoKey[],
): (checkpoint: Uint8Array, detachedPayload: Uint8Array) => Promise<boolean> {
  return async (checkpointBytes, detachedPayload) => {
    const resolution = await resolveDelegatedVerifyKey(
      checkpointBytes,
      rootKeys,
    );
    if (resolution.kind === "broken") return false;
    const candidates =
      resolution.kind === "resolved"
        ? [resolution.delegatedKey, ...rootKeys]
        : rootKeys;
    for (const key of candidates) {
      if (
        await verifyCoseSign1WithParsedKey(checkpointBytes, key, {
          logPrefix: "checkpoint-chain",
          detachedPayload,
        })
      ) {
        return true;
      }
    }
    return false;
  };
}

/**
 * The checkpoint-chain root: fold the retained `.sth` chain, then match the
 * receipt against ANY authenticated link — later links' signed consistency
 * proofs commit an earlier accumulator forward, so burial never turns an
 * honest receipt tamper-shaped.
 *
 * Newest-first, mirroring the `forestrie` CLI: the freshest cover gives the
 * most useful report. Retention limits coverage, never validity, so a receipt
 * newer than the whole chain fails CLOSED with a refresh remedy.
 */
export async function verifyAtCheckpointChain(input: {
  receiptCbor: Uint8Array;
  idtimestampBe8: Uint8Array;
  inner: Uint8Array;
  checkpoints: readonly Uint8Array[];
  rootKeys: CryptoKey[];
}): Promise<AnchoredOutcome> {
  if (input.rootKeys.length === 0) {
    throw new VerifyInputError(
      "the checkpoint-chain root needs an ES256 trust root: supply `genesis` or `keyXy` alongside `checkpoints`",
    );
  }
  const chain = await verifyCheckpointChain({
    checkpoints: [...input.checkpoints],
    verifySignature: makeCheckpointSignatureVerifier(input.rootKeys),
  });
  if (!chain.ok) {
    throw new VerifyInputError(
      `checkpoint chain did not verify (${chain.reason} at link ${chain.at}): ${chain.detail}`,
    );
  }
  const links: CheckpointChainLink[] = chain.links;
  const final = links[links.length - 1];
  if (final === undefined) {
    throw new VerifyInputError("checkpoint chain folded to zero links");
  }

  let last: ReceiptVerifyResult = {
    ok: false,
    stage: "signature",
    reason: "peak_not_in_checkpoint_chain",
  };
  for (let i = links.length - 1; i >= 0; i--) {
    const link = links[i];
    if (link === undefined) continue;
    const attempt = await verifyReceiptOfflineAgainstKnownAccumulator({
      receiptCbor: input.receiptCbor,
      idtimestampBe8: input.idtimestampBe8,
      inner: input.inner,
      accumulator: link.accumulator,
      size: final.treeSize2,
    });
    if (attempt.ok) {
      const matchedPeak = await findMatchedPeak(
        {
          receiptCbor: input.receiptCbor,
          idtimestampBe8: input.idtimestampBe8,
          inner: input.inner,
        },
        link.accumulator,
      );
      return {
        result: attempt,
        anchor: {
          anchored: true,
          anchoredSize: link.treeSize2.toString(),
          peakCount: link.accumulator.length,
          matchedPeak,
          linkCount: links.length,
          matchedLinkSize: link.treeSize2.toString(),
        },
      };
    }
    last = attempt;
    // A parse failure or a newer-than-chain receipt is the same at every
    // link; no point re-asking the older ones.
    if (attempt.stage === "parse") break;
    if (attempt.reason === "receipt_newer_than_known_accumulator") break;
  }

  // Rename the reason to name the anchor the caller actually supplied: they
  // handed us a checkpoint chain, not a snapshot, and "refresh the
  // accumulator" would be the wrong remedy.
  const reason =
    last.stage === "parse"
      ? last.reason
      : last.reason === "receipt_newer_than_known_accumulator"
        ? "receipt_newer_than_checkpoint_chain"
        : "peak_not_in_checkpoint_chain";
  const result: ReceiptVerifyResult = { ok: false, stage: last.stage };
  if (reason !== undefined) result.reason = reason;
  return {
    result,
    anchor: {
      anchored: false,
      anchoredSize: final.treeSize2.toString(),
      peakCount: final.accumulator.length,
      matchedPeak: null,
      linkCount: links.length,
      ...(reason !== undefined ? { reason } : {}),
    },
  };
}

/**
 * Under a caller-known key, a broken delegation chain means the certificate
 * did not verify under the CALLER's key — a different trust failure from a
 * genesis-rooted `delegation_invalid` (wrong known key, or a forged cert).
 * Rename it so the operator reaches for "check the key you were given", not
 * "check the log's delegation". Ported from forestrie-cli's
 * `remapKnownKeyFailure`, so both report the same reason.
 */
export function remapKnownKeyFailure(
  result: ReceiptVerifyResult,
): ReceiptVerifyResult {
  if (!result.ok && result.reason === "delegation_invalid") {
    return { ...result, reason: "known_key_mismatch" };
  }
  return result;
}

export type AssembleInput = {
  root: RootName;
  kind: ReceiptKind;
  result: ReceiptVerifyResult;
  detachedPayload: boolean | undefined;
  anchor?: AnchorReport | undefined;
};

/** Build the result from the mechanical verdict plus the root context. */
export function assembleResult(input: AssembleInput): VerifyResult {
  const anchoredRoot = rootAnswersSplitView(input.root);
  const rows =
    input.root === "known-log-key"
      ? knownKeyStageRows(input.result)
      : anchoredRoot
        ? anchoredStageRows(input.result)
        : stageRows(input.result);

  const questionsInput = {
    root: input.root,
    kind: input.kind,
    ok: input.result.ok,
    stage: input.result.stage,
    detachedPayload: input.detachedPayload === true,
    anchored: input.anchor?.anchored,
  };

  const out: VerifyResult = {
    ok: input.result.ok,
    root: input.root,
    stage: input.result.stage,
    stages: rows,
    questions: trustQuestions(questionsInput),
    diagnostics: diagnosticsFor(questionsInput),
    verifier: {
      package: "@forestrie/mcp-verify",
      version: PACKAGE_VERSION,
      receiptVerify: RECEIPT_VERIFY_VERSION,
    },
  };
  if (input.result.reason !== undefined) out.reason = input.result.reason;
  if (input.anchor !== undefined) out.anchor = input.anchor;
  return out;
}

/**
 * A result for an input that never reached the arithmetic — a root whose
 * bytes did not decode, say. Reported as a clean `parse` failure rather than
 * a thrown stack trace, because the `forestrie` CLI's habit of
 * crashing on a missing required argument is exactly what this layer exists not to reproduce.
 */
export function inputFailureResult(
  root: RootName,
  kind: ReceiptKind,
  reason: string,
): VerifyResult {
  return assembleResult({
    root,
    kind,
    result: { ok: false, stage: "parse", reason },
    detachedPayload: undefined,
  });
}

/**
 * The sentence a human reads in an agent transcript. It must never be a bare
 * "valid": the anchor and the unanswered questions are the point.
 *
 * `verify-grant: FAILED at signature (signature_invalid) · root=genesis · sealing failed, split-view not answered at this root`
 */
export function summarize(verb: string, result: VerifyResult): string {
  const head = result.ok
    ? `${verb}: PASS`
    : `${verb}: FAILED at ${result.stage}${
        result.reason !== undefined ? ` (${result.reason})` : ""
      }`;
  const answered = (
    ["sealing", "split-view", "append-authority", "attribution"] as const
  ).map((q) => {
    const a = result.questions[q];
    return `${q} ${
      a.status === "not_answered_by_this_root"
        ? "not answered at this root"
        : a.status
    }`;
  });
  return `${head} · root=${result.root} · ${answered.join(", ")}`;
}

/** Exported for tests that assert the stage vocabulary has not drifted. */
export { VERIFY_STAGES };

export type { Diagnostic };
