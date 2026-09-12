/**
 * D3: the result carries BOTH enumerations, because they are different
 * things.
 *
 * 1. `stages[]` — the mechanical stages the arithmetic actually ran, exactly
 *    the reference CLI's `VerifyReport` contract. This is the differential
 *    test's target and it is not ours to reinterpret.
 * 2. `questions` — rule P3's four trust questions, which are the product's
 *    answers. Each is `ok | failed | not_answered_at_this_rung`.
 *
 * The second exists because the first is not enough. A bare "valid" is the
 * failure mode this package was built to remove: valid *under what anchor*,
 * answering *which* questions? A stage table cannot say. `questions` can, and
 * `diagnostics[]` names the sharp edges by machine-readable code.
 */
import type { ReceiptVerifyStage } from "@forestrie/receipt-verify";
import type { RungName } from "./rung.js";

export type { ReceiptVerifyStage };

/** Mechanical stage status — forestrie-cli/src/lib/verify-report.ts:28-34. */
export type StageStatus = "ok" | "failed" | "skipped";

export type StageRow = {
  stage: ReceiptVerifyStage;
  status: StageStatus;
  reason?: string;
};

/** P3's four trust questions — the product's answers. */
export type QuestionName =
  "split-view" | "sealing" | "append-authority" | "attribution";

export type QuestionStatus = "ok" | "failed" | "not_answered_at_this_rung";

export type QuestionAnswer = { status: QuestionStatus; note: string };

export type TrustQuestions = Record<QuestionName, QuestionAnswer>;

export const QUESTION_NAMES = [
  "split-view",
  "sealing",
  "append-authority",
  "attribution",
] as const satisfies readonly QuestionName[];

/**
 * Named, machine-readable notes. A diagnostic is not a warning: it is a
 * statement about what the arithmetic could and could not separate, emitted
 * so an agent does not have to infer it from a stage name.
 */
export type DiagnosticCode =
  /** Detached payload + no independent accumulator: a bad proof and a bad
   *  signature are the same observation. Plan-2609-02 D3, the collapse. */
  | "detached_payload_stage_collapse"
  /** This rung has no independent accumulator, so split-view is unanswered. */
  | "rung_answers_no_split_view"
  /** verify_receipt does not walk a grant chain; append-authority is unanswered. */
  | "grant_authority_not_checked_for_payload_receipt"
  /** Upstream labels a peak/staleness failure at the accumulator rung as
   *  stage=signature although no signature was evaluated. Passed through
   *  verbatim for differential fidelity; named here so nobody misreads it. */
  | "accumulator_failure_reported_at_signature_stage";

export type Diagnostic = { code: DiagnosticCode; message: string };

export type VerifierIdentity = {
  package: "@forestrie/mcp-verify";
  version: string;
  /** The exact @forestrie/receipt-verify version whose arithmetic ran. */
  receiptVerify: string;
};

/** `--json` anchor block. Sizes are decimal strings, mirroring the CLI's
 *  AnchorReport (forestrie-cli/src/lib/verify-report.ts:146-171). */
export type AnchorReport = {
  anchored: boolean;
  anchoredSize: string;
  peakCount: number;
  matchedPeak: number | null;
  reason?: string;
  /** known-accumulator anchors only: the audited chain read. */
  blockNumber?: string;
  blockHash?: string;
  univocity?: string;
  logId?: string;
  /** checkpoint-chain anchors only: links folded, and the sealed size of the
   *  link that held the peak. */
  linkCount?: number;
  matchedLinkSize?: string;
};

/**
 * The tool result. A superset of the CLI's `VerifyReport` on the four fields
 * the differential test compares (`ok`, `stage`, `reason`, `stages`);
 * `questions`, `diagnostics` and `verifier` are ours alone.
 */
export type VerifyResult = {
  ok: boolean;
  rung: RungName;
  stage: ReceiptVerifyStage;
  reason?: string;
  stages: StageRow[];
  anchor?: AnchorReport;
  questions: TrustQuestions;
  diagnostics: Diagnostic[];
  verifier: VerifierIdentity;
};
