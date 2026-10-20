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
  decodeChainBindingFromGenesis,
  decodeKs256Attestation,
  importEs256PublicKeyFromGrantDataXy64,
  knownLogKeyFromBytes,
  parseReceipt,
  verifyReceiptAgainstCheckpointChain,
  verifyReceiptOfflineAgainstKnownAccumulator,
  type CheckpointLinkRecord,
  type Ks256Attestation,
  type ReceiptVerifyResult,
  type RootVerifyKey,
} from "@forestrie/receipt-verify";
import { bytesEqual, recomputeReceiptPeak } from "./peak.js";
import type {
  AnchorReport,
  Diagnostic,
  Ks256AttestationReport,
  Ks256AttestationsReport,
  VerifyResult,
} from "./result.js";
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
 * The `known-log-key` root's key: exactly one of `keyXy` (64-byte ES256) or
 * `ks256Address` (20-byte KS256), parsed through `knownLogKeyFromBytes`.
 * Either way the key-to-log binding is ASSERTED by the caller, not proven.
 */
export async function resolveKnownLogKey(trust: {
  keyXy?: Uint8Array | undefined;
  ks256Address?: Uint8Array | undefined;
}): Promise<RootVerifyKey> {
  if (trust.keyXy !== undefined && trust.ks256Address !== undefined) {
    throw new VerifyInputError(
      "known-log-key takes exactly one of keyXy (64-byte P-256 x‖y) or ks256Address (20 bytes), not both",
    );
  }
  if (trust.ks256Address !== undefined) {
    if (trust.ks256Address.length !== 20) {
      throw new VerifyInputError(
        `ks256Address must be a 20-byte address, got ${trust.ks256Address.length}`,
      );
    }
    return knownLogKeyFromBytes(trust.ks256Address);
  }
  if (trust.keyXy === undefined) {
    throw new VerifyInputError(
      "known-log-key needs exactly one of keyXy (64-byte P-256 x‖y) or ks256Address (20 bytes)",
    );
  }
  return importKnownLogKey(trust.keyXy);
}

/** Why a supplied attestation was not needed on a passing run. */
export type AttestationUnused = "ecrecover" | "es256-root" | "not-needed";

/** What the supplied attestations contribute to a run, resolved against the root. */
export type AttestationPlan = {
  attestations: Ks256Attestation[];
  /**
   * The forest genesis, read for its chain id alone: `forestGenesis` under
   * known-log-key, the supplied `genesis` under checkpoint-chain.
   */
  forestGenesisCbor?: Uint8Array;
};

/**
 * The attestation bytes a caller supplied, from the singular and the plural
 * input fields: the singular first, then the list, in the order given.
 */
export function attestationInputs(input: {
  ks256Attestation?: Uint8Array | undefined;
  ks256Attestations?: readonly Uint8Array[] | undefined;
}): Uint8Array[] {
  return [
    ...(input.ks256Attestation !== undefined ? [input.ks256Attestation] : []),
    ...(input.ks256Attestations ?? []),
  ];
}

/**
 * Decode the supplied ERC-1271 attestations and check the root can use them.
 * The `genesis`, `known-log-key` and `checkpoint-chain` roots verify a
 * delegation certificate against a KS256 root; `known-accumulator` has no
 * such step, so an attestation there would be silently ignored — reject it.
 * `checkpoint-chain` additionally needs its `genesis` (the forest chain id).
 */
export function planAttestation(
  trust: TrustRoot,
  attestationBytes: readonly Uint8Array[],
): AttestationPlan {
  if (trust.root === "known-log-key" && trust.forestGenesis !== undefined) {
    // Only the chain id is used, so it must decode as a forest genesis that
    // carries a chain binding; anything else would surface later as a
    // verdict-shaped failure about the receipt.
    try {
      decodeChainBindingFromGenesis(trust.forestGenesis);
    } catch (err) {
      throw new VerifyInputError(
        `forestGenesis is not a forest genesis with a chain binding: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
  }
  if (attestationBytes.length === 0) return { attestations: [] };
  if (trust.root === "known-accumulator") {
    throw new VerifyInputError(
      "ks256Attestation is only usable with the genesis, known-log-key and checkpoint-chain roots, not known-accumulator: that root never checks a delegation certificate against a KS256 root",
    );
  }
  if (trust.root === "checkpoint-chain") {
    if (trust.genesis === undefined) {
      throw new VerifyInputError(
        "ks256Attestation under checkpoint-chain needs trust.genesis for the forest chain: the attestation is bound to the genesis chain id, and a bare keyXy carries none",
      );
    }
    try {
      decodeChainBindingFromGenesis(trust.genesis);
    } catch (err) {
      throw new VerifyInputError(
        `ks256Attestation under checkpoint-chain needs a genesis with a chain binding: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
  }
  const attestations = attestationBytes.map((bytes, i) => {
    try {
      return decodeKs256Attestation(bytes);
    } catch (err) {
      throw new VerifyInputError(
        `ks256Attestation is not a valid attestation artifact${
          attestationBytes.length > 1 ? ` (entry ${i})` : ""
        }: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  });
  const plan: AttestationPlan = { attestations };
  if (trust.root === "known-log-key" && trust.forestGenesis !== undefined) {
    plan.forestGenesisCbor = trust.forestGenesis;
  }
  if (trust.root === "checkpoint-chain" && trust.genesis !== undefined) {
    plan.forestGenesisCbor = trust.genesis;
  }
  return plan;
}

/** What the attestations contributed to a run, as the result reports it. */
export type AttestationOutcome = {
  ks256Attestations?: Ks256AttestationsReport;
  /** Why unneeded attestations were not needed, when that is the reason. */
  attestationUnusedLabel?: AttestationUnused;
};

/**
 * What the attestations contributed to a run through the receipt-level
 * verifiers (`genesis`, `known-log-key`). The same pure verify is re-run:
 * without any attestation, and if that also passes the root verified by
 * ecrecover (or an ES256 root) and none was needed, so no attested guarantee
 * is claimed; otherwise each attestation is tried alone, and the first that
 * carries the run is the one used. Offline, cheap, no chain call either way.
 * A failing run reports every attestation as unused (`run_failed`): none
 * carried it.
 */
export async function attestationOutcome(
  plan: AttestationPlan,
  result: ReceiptVerifyResult,
  rerun: (attestations: Ks256Attestation[]) => Promise<ReceiptVerifyResult>,
  rootKey: () => Promise<RootVerifyKey>,
): Promise<AttestationOutcome> {
  const atts = plan.attestations;
  if (atts.length === 0) return {};
  if (!result.ok) {
    return {
      ks256Attestations: {
        used: [],
        unused: atts.map((a, index) => unusedEntry(a, index, "run_failed")),
      },
    };
  }
  if ((await rerun([])).ok) {
    // Why they were not needed: an ES256 root never consults an attestation;
    // a KS256 EOA root verified by ecrecover.
    return {
      ks256Attestations: {
        used: [],
        unused: atts.map((a, index) => unusedEntry(a, index, "not_needed")),
      },
      attestationUnusedLabel:
        (await rootKey()) instanceof CryptoKey ? "es256-root" : "ecrecover",
    };
  }
  const passesAlone: boolean[] = [];
  for (const a of atts) passesAlone.push((await rerun([a])).ok);
  // The first that carries the run is the one used; if none does alone
  // (cannot happen for a single certificate), credit the first.
  const usedIndex = Math.max(0, passesAlone.indexOf(true));
  return {
    ks256Attestations: {
      used: [usedEntry(atts[usedIndex]!, usedIndex)],
      unused: atts
        .map((a, index) =>
          index === usedIndex
            ? null
            : unusedEntry(
                a,
                index,
                passesAlone[index] ? "not_needed" : "no_matching_certificate",
              ),
        )
        .filter((e) => e !== null),
    },
  };
}

function usedEntry(
  a: Ks256Attestation,
  index: number,
  links?: number[],
): Ks256AttestationsReport["used"][number] {
  return {
    index,
    digest: `0x${bytesToHex(a.digest)}`,
    ...(links !== undefined ? { links } : {}),
    ...attestationReport(a),
  };
}

function unusedEntry(
  a: Ks256Attestation,
  index: number,
  reason: string,
): Ks256AttestationsReport["unused"][number] {
  return { index, digest: `0x${bytesToHex(a.digest)}`, reason };
}

/** The result block naming the chain and block an attestation speaks for. */
export function attestationReport(
  a: Ks256Attestation,
): Ks256AttestationReport {
  return {
    chainId: a.chainId.toString(),
    blockNumber: a.blockNumber.toString(),
    blockHash: `0x${bytesToHex(a.blockHash)}`,
    address: `0x${bytesToHex(a.address)}`,
  };
}

/**
 * Name a mechanism for unneeded attestations only when every link verified
 * the same way; with a mix (an ES256 key and a KS256 genesis root both in
 * play) just say they were not needed.
 */
function unusedLabelFromRecords(
  records: readonly CheckpointLinkRecord[],
): AttestationUnused {
  const kinds = new Set(
    records.map((r) =>
      r.verifiedBy === "ks256-root" ? "ecrecover" : "es256-root",
    ),
  );
  if (kinds.size === 1) return [...kinds][0] as AttestationUnused;
  return "not-needed";
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
  anchor?: AnchorReport;
  /** checkpoint-chain only: the typed stage of a failure. */
  chainStage?: string;
  /** checkpoint-chain only: the human detail of a chain-level failure. */
  detail?: string;
  /** checkpoint-chain only: the link a chain-level failure names. */
  failedLink?: number;
  /** checkpoint-chain only: used and unused attestations. */
  ks256Attestations?: Ks256AttestationsReport;
  attestationUnusedLabel?: AttestationUnused;
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
 * The checkpoint-chain root: `@forestrie/receipt-verify`'s shared verifier
 * (`verifyReceiptAgainstCheckpointChain`, lifted from this package's 0.6.1
 * copy) folds the retained `.sth` chain under the caller's roots with each
 * delegation certificate's limits enforced per link, matches the receipt's
 * leaf-derived peak against ANY authenticated link, and judges expiry on the
 * links that cover the now-bound leaf. This function only maps its typed
 * outcome onto this package's result: `stage`/`reason` are the typed ones,
 * not a thrown string with a `[delegation: X]` suffix.
 *
 * Retention limits coverage, never validity, so a receipt newer than the
 * whole chain fails CLOSED with a refresh remedy.
 */
export async function verifyAtCheckpointChain(input: {
  receiptCbor: Uint8Array;
  idtimestampBe8: Uint8Array;
  inner: Uint8Array;
  checkpoints: readonly Uint8Array[];
  rootKeys: RootVerifyKey[];
  /** ERC-1271 attestations for a KS256 contract root, with its genesis. */
  attestation?: AttestationPlan;
}): Promise<AnchoredOutcome> {
  if (input.rootKeys.length === 0) {
    throw new VerifyInputError(
      "the checkpoint-chain root needs a trust root: supply `genesis` or `keyXy` alongside `checkpoints`",
    );
  }
  const atts = input.attestation?.attestations ?? [];
  const genesis = input.attestation?.forestGenesisCbor;
  const out = await verifyReceiptAgainstCheckpointChain({
    receiptCbor: input.receiptCbor,
    idtimestampBe8: input.idtimestampBe8,
    inner: input.inner,
    checkpoints: input.checkpoints,
    rootKeys: input.rootKeys,
    ...(atts.length > 0 ? { attestations: atts } : {}),
    ...(genesis !== undefined ? { forestGenesisCbor: genesis } : {}),
  });

  const attestationReport: Pick<
    AnchoredOutcome,
    "ks256Attestations" | "attestationUnusedLabel"
  > = {};
  if (atts.length > 0) {
    attestationReport.ks256Attestations = {
      used: out.attestations.used.map((u) =>
        usedEntry(atts[u.index]!, u.index, u.links),
      ),
      unused: out.attestations.unused.map((u) =>
        unusedEntry(atts[u.index]!, u.index, u.reason),
      ),
    };
    if (out.ok && out.attestations.used.length === 0) {
      attestationReport.attestationUnusedLabel = unusedLabelFromRecords(
        out.records,
      );
    }
  }

  const final = out.links[out.links.length - 1];
  if (out.ok) {
    const link = out.links[out.matchedLink]!;
    return {
      result: { ok: true, stage: "binding" },
      anchor: {
        anchored: true,
        anchoredSize: link.treeSize2.toString(),
        peakCount: link.accumulator.length,
        matchedPeak: out.matchedPeak,
        linkCount: out.links.length,
        matchedLinkSize: link.treeSize2.toString(),
      },
      ...attestationReport,
    };
  }

  // Map the typed stage onto the CLI's stage vocabulary. A bad input or an
  // unreadable receipt is `parse`; everything else the chain refused is
  // `signature` (the label upstream uses for an accumulator that did not
  // match, too — the typed `reason` carries the real verdict).
  const stage: ReceiptVerifyResult["stage"] =
    out.stage === "input" || out.stage === "parse" ? "parse" : "signature";
  const outcome: AnchoredOutcome = {
    result: { ok: false, stage, reason: out.reason },
    ...attestationReport,
  };
  if (out.stage === "chain") {
    outcome.detail = `checkpoint chain did not verify${
      out.at !== undefined ? ` at link ${out.at}` : ""
    }${out.detail !== undefined ? `: ${out.detail}` : ""}`;
  } else if (out.stage === "delegation") {
    outcome.detail = `checkpoint ${out.at ?? "?"} was signed under a delegation certificate that had expired when the receipt's leaf was sequenced`;
  }
  outcome.chainStage = out.stage;
  if (out.at !== undefined) outcome.failedLink = out.at;
  if (out.stage === "anchor" && final !== undefined) {
    // The chain folded and its signatures held: this is an anchor verdict.
    outcome.anchor = {
      anchored: false,
      anchoredSize: final.treeSize2.toString(),
      peakCount: final.accumulator.length,
      matchedPeak: null,
      linkCount: out.links.length,
      reason: out.reason,
    };
  }
  return outcome;
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
  /** Set when the run was given ERC-1271 attestations: used and unused. */
  ks256Attestations?: Ks256AttestationsReport | undefined;
  /** Why unneeded attestations were not needed, when a label applies. */
  attestationUnusedLabel?: AttestationUnused | undefined;
  /** checkpoint-chain: the typed stage of a failure (`chain`, `delegation`, ...). */
  chainStage?: string | undefined;
  /** A chain-level failure's human detail, and the link it names. */
  detail?: string | undefined;
  failedLink?: number | undefined;
};

/** Build the result from the mechanical verdict plus the root context. */
export function assembleResult(input: AssembleInput): VerifyResult {
  const anchoredRoot = rootAnswersSplitView(input.root);
  const used = input.ks256Attestations?.used ?? [];
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
    reason: input.result.reason,
    attested: used.length > 0,
    attestationUnused: input.attestationUnusedLabel,
    attestedAt: used.map((u) => ({
      chainId: u.chainId,
      blockNumber: u.blockNumber,
    })),
    unusedAttestations: input.ks256Attestations?.unused ?? [],
    chainStage: input.chainStage,
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
  if (input.detail !== undefined) out.detail = input.detail;
  if (input.failedLink !== undefined) out.failedLink = input.failedLink;
  if (input.ks256Attestations !== undefined) {
    out.ks256Attestations = input.ks256Attestations;
    // The first attestation that carried the run, in the 0.6 singular shape.
    const first = used[0];
    if (first !== undefined) {
      out.ks256Attestation = {
        chainId: first.chainId,
        blockNumber: first.blockNumber,
        blockHash: first.blockHash,
        address: first.address,
      };
    }
  }
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
