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

export type { TrustRung, RungName } from "./rung.js";
export { RUNG_NAMES, isTrustRung, rungAnswersSplitView } from "./rung.js";

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

export type { RecomputedPeak } from "./peak.js";
/** Recompute a receipt's MMR peak from leaf + inclusion path. Exposed because
 *  building a known-accumulator snapshot for a receipt you hold needs it, and
 *  because it is the value the whole ladder turns on. */
export { recomputeReceiptPeak } from "./peak.js";

export type { VerifyReceiptInput } from "./verify-receipt.js";
/** Payload receipt: exact registered payload + entry id + rung.
 *  Mirrors `forestrie verify`. */
export { verifyReceipt } from "./verify-receipt.js";

export type { VerifyGrantReceiptInput } from "./verify-grant-receipt.js";
/** Grant receipt: committed grant (COSE or raw payload) + rung.
 *  Mirrors `forestrie verify-grant`. */
export { verifyGrantReceipt } from "./verify-grant-receipt.js";

export type {
  DecodedClaim,
  DecodedHeaderEntry,
  DecodedReceipt,
  DecodeReceiptStage,
  Json,
} from "./decode-receipt.js";
/** CBOR → JSON. No verification. Mirrors `forestrie decode-receipt --json`. */
export {
  DecodeReceiptError,
  bytesToHex,
  decodeReceipt,
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
