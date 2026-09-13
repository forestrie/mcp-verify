/**
 * `@forestrie/mcp-verify` — the browser-safe core.
 *
 * This is the `"."` export. Everything reachable from here is pure over
 * bytes: no `node:*`, no `fetch`, no filesystem, no MCP SDK. An importer who
 * takes `"."` gets the arithmetic and nothing else; `"./server"` is where the
 * adapter lives. `pnpm run check:browser-safe` bundles this file for
 * `platform: "browser"` and fails on any edge to a node builtin, so that
 * boundary is proven on every test run and before every publish, not asserted.
 *
 * Every signature takes `Uint8Array`, never a path and never a base64 string.
 * That is what makes the browser-safe gate satisfiable at all: base64 decoding
 * and `{path}` resolution both live in `src/node/resolve-input.ts`.
 */

export type { TrustRoot, RootName } from "./root.js";
export { ROOT_NAMES, isTrustRoot, rootAnswersSplitView } from "./root.js";

export type {
  AnchorReport,
  Diagnostic,
  DiagnosticCode,
  QuestionAnswer,
  QuestionName,
  QuestionStatus,
  ReceiptVerifyStage,
  StageRow,
  StageStatus,
  TrustQuestions,
  VerifierIdentity,
  VerifyResult,
} from "./result.js";
export { QUESTION_NAMES } from "./result.js";

export type { ReceiptKind } from "./questions.js";

export {
  ANCHORED_SIGNATURE_REASON,
  KNOWN_KEY_PARSE_REASON,
  KNOWN_KEY_SIGNATURE_REASON,
  STAGE_NARRATION,
  VERIFY_STAGES,
  stageRows,
} from "./stages.js";

export { VerifyInputError, summarize } from "./verify-shared.js";

/** What `recomputeReceiptPeak` returns: the MMR peak the receipt's inclusion
 *  path commits to, plus the leaf's MMR index. The peak is what gets compared
 *  against a known accumulator; the leaf index bounds the snapshot coverage
 *  that comparison is valid for. */
export type { RecomputedPeak } from "./peak.js";
/** Recompute a receipt's MMR peak from leaf + inclusion path. Exposed because
 *  building a known-accumulator snapshot for a receipt you hold needs it, and
 *  because it is the value every trust root turns on. */
export { recomputeReceiptPeak } from "./peak.js";

export type { VerifyReceiptInput } from "./verify-receipt.js";
/** Payload receipt: exact registered payload + entry id + root.
 *  Mirrors `forestrie verify`. */
export { verifyReceipt } from "./verify-receipt.js";

export type { VerifyGrantReceiptInput } from "./verify-grant-receipt.js";
/** Grant receipt: committed grant (COSE or raw payload) + root.
 *  Mirrors `forestrie verify-grant`. */
export { verifyGrantReceipt } from "./verify-grant-receipt.js";

export type {
  SelfBundle,
  SelfProvenance,
  SelfVerifyResult,
  VerifySelfOptions,
} from "./verify-self.js";
/** This package's own release-time self-registration bundle (plan-2609-02
 *  step 2.4). Defaults to the `known-log-key` root with the bundle's own
 *  key — see docs/self-registration.md for why `genesis` is not the
 *  default. */
export { summarizeSelf, verifySelf } from "./verify-self.js";

export type {
  DecodedClaim,
  DecodedHeaderEntry,
  DecodedReceipt,
  DecodeReceiptStage,
  Json,
  LabelInfo,
} from "./decode-receipt.js";
/** CBOR → JSON. No verification. Mirrors `forestrie decode-receipt --json`.
 *
 *  Re-exported from `@forestrie/forestrie-cli@0.8.0`'s published
 *  `/decode-receipt` subpath (plan-2609-02 workstream P step P5.5) —
 *  `src/core/decode-receipt.ts` is a thin re-export, not an implementation.
 *  See that file's header for the one known behavioural difference (two
 *  forestrie private-use label codepoints the CLI's registry does not carry
 *  yet). */
export {
  ALG_NAMES,
  COSE_KEY_PARAM_NAMES,
  COSE_SIGN1_TAG,
  CWT_CLAIMS_LABEL,
  CWT_CLAIM_NAMES,
  DELEGATION_CERT_LABEL,
  DecodeReceiptError,
  HEADER_LABELS,
  PROOFS_CONSISTENCY_KEY,
  PROOFS_INCLUSION_KEY,
  PROOF_KIND_NAMES,
  SEAL_PEAK_RECEIPTS_LABEL,
  VDS_LABEL,
  VDS_NAMES,
  VERIFIABLE_PROOFS_LABEL,
  bytesToHex,
  decodeReceipt,
  headerLabelInfo,
  toJson,
} from "./decode-receipt.js";

import type { VerifierIdentity } from "./result.js";
import { PACKAGE_VERSION, RECEIPT_VERIFY_VERSION } from "./version.js";

export {
  ENCODING_VERSION,
  PACKAGE_VERSION,
  RECEIPT_VERIFY_VERSION,
} from "./version.js";

/** Exposed so the MCP layer and the README can name what they ran. */
export const VERIFIER: VerifierIdentity = {
  package: "@forestrie/mcp-verify",
  version: PACKAGE_VERSION,
  receiptVerify: RECEIPT_VERIFY_VERSION,
};
