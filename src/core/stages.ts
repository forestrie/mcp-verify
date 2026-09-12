/**
 * Port of `forestrie-cli/src/lib/verify-report.ts:113-142`. The `--json`
 * stage shape is a load-bearing contract — the reference CLI's own CI asserts
 * it — so this is a port, not an adaptation. `test/differential/` compares
 * the output of this function against the CLI's byte for byte.
 */
import type { ReceiptVerifyResult } from "@forestrie/receipt-verify";
import type { ReceiptVerifyStage, StageRow } from "./result.js";

/**
 * Verification pipeline in narration order (ADR-0045 layers A–C):
 * https://github.com/forestrie/protocol/blob/main/decisions/adr-0045-receipt-verify-offline-contract.md
 */
export const VERIFY_STAGES: readonly ReceiptVerifyStage[] = [
  "parse",
  "signature",
  "inclusion",
  "binding",
];

/** One line per stage: what a human reads at every step. */
export const STAGE_NARRATION: Record<ReceiptVerifyStage, string> = {
  parse: "receipt COSE decodes; genesis trust root loads (ES256)",
  signature: "checkpoint signature verifies under the genesis trust key",
  inclusion: "proof path recomputes the checkpoint peak",
  binding: "leaf commits the payload (SHA-256) at the receipt idtimestamp",
};

export const KNOWN_KEY_PARSE_REASON =
  "receipt COSE decodes; caller-known log key loads (ES256)";
export const KNOWN_KEY_SIGNATURE_REASON =
  "verifies under caller-known log key (not genesis-derived)";

/**
 * The known-accumulator root's own narration. Upstream's
 * `verifyReceiptOfflineAgainstKnownAccumulator` evaluates no signature at
 * all; a `signature: ok` row there would be a lie by omission unless it says
 * WHY it is ok. It is the same argument the CLI makes in
 * `SIGNATURE_ANCHORED_REASON`: univocity refuses to publish a checkpoint
 * whose signature does not verify under the log's live delegation, so an
 * anchored peak match implies a valid publishing signature.
 */
export const ANCHORED_SIGNATURE_REASON =
  "not re-checked locally — enforced by univocity at publish; " +
  "an anchored peak match implies a valid publishing signature";

/**
 * Expand the library's `{ok, stage, reason}` into one row per stage: on
 * success all four pass; on failure the reported stage failed, earlier stages
 * passed, later stages were not reached.
 *
 * A stage this package does not know (a future `@forestrie/receipt-verify`
 * addition) still renders explicitly as the failed row — degrading it to four
 * silent "skipped" rows would HIDE the failure (F3, plan-2607-14 W1.3). We
 * cannot order an unknown stage among the known ones, so the known stages
 * read "skipped" (not evaluated by this package's knowledge) and the unknown
 * stage carries the failure. Do not "simplify" this branch away.
 */
export function stageRows(result: ReceiptVerifyResult): StageRow[] {
  if (result.ok) {
    return VERIFY_STAGES.map((stage) => ({ stage, status: "ok" as const }));
  }
  const failedAt = VERIFY_STAGES.indexOf(result.stage);
  if (failedAt === -1) {
    return [
      ...VERIFY_STAGES.map((stage) => ({
        stage,
        status: "skipped" as const,
      })),
      {
        stage: result.stage,
        status: "failed" as const,
        reason: result.reason ?? "unknown",
      },
    ];
  }
  return VERIFY_STAGES.map((stage, i) => {
    if (i < failedAt) return { stage, status: "ok" as const };
    if (i === failedAt) {
      return {
        stage,
        status: "failed" as const,
        reason: result.reason ?? "unknown",
      };
    }
    return { stage, status: "skipped" as const };
  });
}

/** Stage rows for a run anchored on a caller-known log key (FOR-297 D1). */
export function knownKeyStageRows(result: ReceiptVerifyResult): StageRow[] {
  return stageRows(result).map((row) => {
    if (row.status !== "ok") return row;
    if (row.stage === "parse")
      return { ...row, reason: KNOWN_KEY_PARSE_REASON };
    if (row.stage === "signature")
      return { ...row, reason: KNOWN_KEY_SIGNATURE_REASON };
    return row;
  });
}

/** Stage rows for a run whose only authority is a trusted accumulator. */
export function anchoredStageRows(result: ReceiptVerifyResult): StageRow[] {
  return stageRows(result).map((row) => {
    if (row.status !== "ok") return row;
    if (row.stage === "signature")
      return { ...row, reason: ANCHORED_SIGNATURE_REASON };
    return row;
  });
}
