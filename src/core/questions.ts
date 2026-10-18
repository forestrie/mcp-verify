/**
 * The root → four-questions mapping, plus the collapse diagnostic.
 *
 * The mapping is root-dependent, and that is the entire point of the Auditor:
 * the same bytes answer more questions under an accumulator root, and the
 * tool says which — never a bare "valid".
 *
 * | Root                              | sealing  | split-view       | append-authority | attribution |
 * |-----------------------------------|----------|------------------|------------------|-------------|
 * | genesis / known-log-key           | answered | NOT answered     | grant only       | answered    |
 * | known-accumulator / checkpoint-…  | answered | answered         | grant only       | answered    |
 *
 * "NOT answered" at the two signature roots is not a hedge. With a
 * detached-payload receipt the signature covers the MMR peak, which is only
 * knowable after recomputing it from leaf + path — so a bad path and a bad
 * signature are literally the same observation, and no amount of care can
 * separate them without an independent accumulator to check the peak against.
 * That is `detached_payload_stage_collapse`.
 */
import type {
  Diagnostic,
  QuestionAnswer,
  QuestionStatus,
  TrustQuestions,
} from "./result.js";
import type { RootName } from "./root.js";
import { rootAnswersSplitView } from "./root.js";

/** Which receipt kind was verified — decides the `append-authority` answer. */
export type ReceiptKind = "payload" | "grant";

/**
 * The evidence bundle handed to the question generator for a single receipt.
 *
 * It captures everything the questioner needs to decide *which* questions are
 * worth asking about a verification run: which trust root the receipt was checked under
 * (`root`, `kind`), what the arithmetic actually concluded (`ok`, `stage`), and
 * the two conditions that can make a mechanically-`ok` result untrustworthy —
 * a detached COSE payload (`detachedPayload`) and a missing or failed
 * accumulator anchor (`anchored`).
 *
 * Invariants:
 * - `stage` is the last stage reached, whether or not `ok` is `true`.
 * - `anchored` is only meaningful at the accumulator/checkpoint roots;
 *   `undefined` means the check never ran and must not be read as a failure.
 * - `detachedPayload === true` is a precondition for stage collapse, not
 *   proof of it.
 */
export type QuestionsInput = {
  root: RootName;
  kind: ReceiptKind;
  /** The mechanical verdict of the arithmetic that actually ran. */
  ok: boolean;
  /** The stage the arithmetic stopped at. */
  stage: string;
  /** True when the receipt's COSE payload is detached (null) — the condition
   *  that makes the stage collapse possible at all. */
  detachedPayload: boolean;
  /** Set only at the accumulator/checkpoint roots: did the recomputed peak
   *  match a trusted accumulator? `undefined` means the check never ran. */
  anchored?: boolean | undefined;
  /** The arithmetic's failure reason, when it gave one. */
  reason?: string | undefined;
  /** An ERC-1271 attestation was supplied (and the run passed). */
  attested?: boolean | undefined;
  /** An attestation was supplied but not needed (the root verified by ecrecover). */
  attestationUnused?: "ecrecover" | "es256-root" | undefined;
  /** Chain and block of an attestation the run NEEDED (decimal strings). */
  attestedAt?: { chainId: string; blockNumber: string } | undefined;
};

/** Does this failure reason come from the KS256 root path? */
export function isKs256Reason(reason: string | undefined): boolean {
  return (
    reason !== undefined &&
    (reason.startsWith("ks256_") || reason === "delegation_not_ks256")
  );
}

/** What each KS256 reason means and what to do about it. */
export const KS256_REASON_NOTES: Record<string, string> = {
  ks256_root_not_recovered:
    "The delegation certificate's secp256k1 signature did not recover to the KS256 root address. Offline that is either a wrong signer or a contract root (a Safe); for a contract, supply a ks256Attestation (fetched elsewhere) bound to this certificate.",
  delegation_not_ks256:
    "The root is a KS256 address but the delegation certificate is not KS256-signed (wrong algorithm, WebAuthn envelope, or malformed).",
  ks256_root_requires_delegation:
    "The root is a KS256 address, which can only vouch for a delegation certificate, but the receipt carries none.",
  ks256_attestation_address_mismatch:
    "The attestation was made for a different contract address than the root.",
  ks256_attestation_digest_mismatch:
    "The attestation covers a different certificate digest than this receipt's delegation certificate.",
  ks256_attestation_signature_mismatch:
    "The attestation's signature hash does not match this receipt's delegation certificate signature.",
  ks256_attestation_chain_mismatch:
    "The attestation was made on a different chain than the forest's genesis chain; the same address on another chain can have other owners.",
  ks256_attestation_magic_invalid:
    "The attested isValidSignature call did not return the ERC-1271 magic value.",
  ks256_attestation_chain_unbound:
    "An attestation was supplied but its chain cannot be checked against a forest chain binding.",
};

/** Root-specific remedy for ks256_attestation_chain_unbound. */
function chainUnboundNote(root: RootName): string {
  if (root === "known-log-key") {
    return "An attestation was supplied but no forest genesis, so its chain cannot be checked. Supply trust.forestGenesis (read only for its chain id).";
  }
  return "An attestation was supplied but the genesis document carries no chain binding (no chain id), so the attestation cannot be bound to a chain.";
}

const NOT_ANSWERED: QuestionStatus = "not_answered_by_this_root";

const ROOT_ANCHOR_NOTE: Record<RootName, string> = {
  genesis: "trust root derived from the log's genesis document",
  "known-log-key": "trust root is a log owner key you supplied out of band",
  "known-accumulator":
    "trust root is a caller-held on-chain accumulator snapshot",
  "checkpoint-chain":
    "trust root is a retained checkpoint chain folded from its base",
};

function answer(status: QuestionStatus, note: string): QuestionAnswer {
  return { status, note };
}

/**
 * `sealing` — did the log operator's signature hold?
 *
 * Answered at every root, but by two different arguments. At genesis and
 * known-log-key it is a local COSE check. At the accumulator roots no
 * signature is re-checked locally; the answer comes from the contract, which
 * refuses to publish a checkpoint whose signature does not verify. Both are
 * real answers; the note says which one you got.
 */
function sealing(input: QuestionsInput): QuestionAnswer {
  const anchoredRoot = rootAnswersSplitView(input.root);
  if (input.ok && input.attestedAt !== undefined) {
    return answer(
      "ok",
      `valid under the contract's signers at block ${input.attestedAt.blockNumber} on chain ${input.attestedAt.chainId}, trusting the party that fetched the ERC-1271 attestation; this verifier made no chain call (a narrower guarantee than a locally verified signature)`,
    );
  }
  if (input.ok) {
    return answer(
      "ok",
      anchoredRoot
        ? "implied by the anchor: univocity rejects a checkpoint whose signature does not verify"
        : "checkpoint signature verified locally under the root's trust root",
    );
  }
  if (input.stage === "parse") {
    return answer(
      NOT_ANSWERED,
      "the receipt did not decode, so no signature was reached",
    );
  }
  if (isKs256Reason(input.reason)) {
    return answer(
      "failed",
      "the KS256 root could not be tied to the receipt's delegation certificate — see the ks256_root_failure diagnostic",
    );
  }
  if (anchoredRoot) {
    return answer(
      "failed",
      "the recomputed peak is not in the trusted accumulator, so no valid publishing signature covers this receipt",
    );
  }
  return answer(
    "failed",
    input.detachedPayload
      ? "the signature over the recomputed peak did not verify — see the stage-collapse diagnostic"
      : "the checkpoint signature did not verify under the root's trust root",
  );
}

/**
 * `split-view` — is this the same log everyone else sees?
 *
 * The one question the accumulator roots exist to answer. Only an accumulator the caller
 * trusts independently of the log operator can answer it.
 */
function splitView(input: QuestionsInput): QuestionAnswer {
  if (!rootAnswersSplitView(input.root)) {
    return answer(
      NOT_ANSWERED,
      "no independent accumulator at this root: a log that showed you a private branch would verify exactly like this one",
    );
  }
  if (input.stage === "parse") {
    return answer(
      NOT_ANSWERED,
      "the receipt did not decode, so no peak was recomputed to compare",
    );
  }
  if (input.anchored === true || (input.anchored === undefined && input.ok)) {
    return answer(
      "ok",
      "the recomputed peak is one of the peaks in the accumulator you trust",
    );
  }
  return answer(
    "failed",
    "the recomputed peak is NOT in the accumulator you trust — this receipt does not describe the log you anchored to",
  );
}

/**
 * `append-authority` — was the signer entitled to write to this log?
 *
 * Answered by `verify_grant_receipt`, whose leaf IS a grant: verifying the
 * receipt verifies that this grant was committed. `verify_receipt` verifies a
 * payload leaf and walks no grant chain, so it must say so rather than let a
 * reader assume.
 */
function appendAuthority(input: QuestionsInput): QuestionAnswer {
  if (input.kind !== "grant") {
    return answer(
      NOT_ANSWERED,
      "verify_receipt checks a payload leaf and walks no grant chain; use verify_grant_receipt for the append-authority question",
    );
  }
  if (input.stage === "parse") {
    return answer(
      NOT_ANSWERED,
      "the receipt did not decode, so the committed grant was never reached",
    );
  }
  return input.ok
    ? answer(
        "ok",
        "the leaf commits exactly the grant you supplied, so that grant was admitted to this log",
      )
    : answer(
        "failed",
        "the leaf does not commit the grant you supplied at this idtimestamp",
      );
}

/**
 * `attribution` — who was authorised to sign THIS leaf?
 *
 * Answered from the leaf bytes on the endorsed-leaf path: the leaf commits
 * `SHA-256(idtimestamp ‖ SHA-256(payload))`, so a passing binding stage says
 * the exact bytes you hold were sequenced at the exact idtimestamp you
 * claimed. Nothing weaker, and nothing stronger.
 */
function attribution(input: QuestionsInput): QuestionAnswer {
  if (input.stage === "parse") {
    return answer(
      NOT_ANSWERED,
      "the receipt did not decode, so nothing was bound to anything",
    );
  }
  return input.ok
    ? answer(
        "ok",
        "the leaf commits these exact bytes at this exact idtimestamp",
      )
    : answer(
        "failed",
        "the leaf does not commit these bytes at this idtimestamp",
      );
}

export function trustQuestions(input: QuestionsInput): TrustQuestions {
  return {
    sealing: sealing(input),
    "split-view": splitView(input),
    "append-authority": appendAuthority(input),
    attribution: attribution(input),
  };
}

/**
 * The diagnostics for a run. `detached_payload_stage_collapse` is emitted
 * exactly when the root is genesis-or-known-log-key AND the receipt is
 * detached-payload — the stage-collapse claim in executable form. It is emitted on
 * success too: knowing that a PASS could not have distinguished those two
 * failures is as much a part of the trust story as the failure itself.
 */
export function diagnosticsFor(input: QuestionsInput): Diagnostic[] {
  const out: Diagnostic[] = [];
  const anchoredRoot = rootAnswersSplitView(input.root);

  if (!anchoredRoot && input.detachedPayload) {
    out.push({
      code: "detached_payload_stage_collapse",
      message:
        "This receipt has a detached payload, so its signature covers the MMR peak — " +
        "a value only knowable after recomputing it from leaf + inclusion path. At the " +
        `${input.root} root there is no independent accumulator to check that peak against, ` +
        "so a tampered inclusion path, a tampered committed payload and a tampered signature " +
        "are indistinguishable: all three report stage=signature. Re-run at the " +
        "known-accumulator root to separate them.",
    });
  }

  if (!anchoredRoot) {
    out.push({
      code: "root_answers_no_split_view",
      message:
        `The ${input.root} root answers sealing and attribution but not split-view. ` +
        `${ROOT_ANCHOR_NOTE[input.root]}, and that root is not independent evidence about ` +
        "which log state the rest of the world sees. A log that showed you a private branch " +
        "would produce a receipt that verifies exactly like this one.",
    });
  }

  if (!input.ok && isKs256Reason(input.reason)) {
    out.push({
      code: "ks256_root_failure",
      message: `${input.reason}: ${
        input.reason === "ks256_attestation_chain_unbound"
          ? chainUnboundNote(input.root)
          : (KS256_REASON_NOTES[input.reason ?? ""] ??
            "a KS256 root check failed.")
      }`,
    });
  }

  if (input.ok && input.attested === true) {
    out.push({
      code: "ks256_attested_guarantee",
      message:
        "The delegation certificate verified only with the supplied ERC-1271 attestation: " +
        "the contract root is valid under the contract's signers AT THE ATTESTED BLOCK " +
        "(a narrower guarantee than an EOA or ES256 root). This verifier never called the " +
        "chain and trusts the attestation as the fetching party's chain read." +
        (input.root === "known-log-key"
          ? " The forest chain binding (forestGenesis), like the key, is asserted by you, not proven."
          : ""),
    });
  }

  if (input.ok && input.attestationUnused !== undefined) {
    out.push({
      code: "ks256_attestation_not_consulted",
      message:
        input.attestationUnused === "es256-root"
          ? "An ERC-1271 attestation was supplied but does not apply: the root is an ES256 key, " +
            "so the delegation certificate verified under it directly and no attestation is consulted."
          : "An ERC-1271 attestation was supplied but not needed: the KS256 root verified by " +
            "ecrecover (an EOA), so no attested-block caveat applies.",
    });
  }

  if (input.kind === "payload") {
    out.push({
      code: "grant_authority_not_checked_for_payload_receipt",
      message:
        "verify_receipt proves that these payload bytes were sequenced at this idtimestamp. " +
        "It does not check that whoever registered them held a grant to write to this log; " +
        "that is verify_grant_receipt's question.",
    });
  }

  if (
    anchoredRoot &&
    !input.ok &&
    input.stage === "signature" &&
    input.anchored === false
  ) {
    out.push({
      code: "accumulator_failure_reported_at_signature_stage",
      message:
        "stage=signature here is @forestrie/receipt-verify's label for an accumulator " +
        "check that failed, not the result of evaluating a signature — no signature was " +
        "evaluated at this root. The reason field carries the real verdict " +
        "(peak_not_in_known_accumulator or receipt_newer_than_known_accumulator). " +
        "Passed through verbatim so stages[] stays comparable with the reference CLI.",
    });
  }

  return out;
}
