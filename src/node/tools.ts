/**
 * zod input schemas and `outputSchema`s for the three phase-1 tools.
 *
 * O2, resolved against a live SDK rather than guessed:
 * `@modelcontextprotocol/sdk@1.30.0` accepts zod-4 schemas directly for both
 * `inputSchema` and `outputSchema` and emits draft-07 JSON Schema itself — no
 * `z.toJSONSchema()` at the call site. It wants a **raw shape**
 * (`{ key: ZodType }`) rather than a `ZodObject`, which is also what types the
 * handler's argument correctly, so composite types live as property values.
 * See docs/dependency-surface.md §3; test/node/mcp-smoke.test.ts keeps it true.
 */
import { z } from "zod";

/** Bytes cross the MCP boundary as base64; stdio additionally accepts a path. */
export const BytesInputSchema = z
  .union([
    z.object({ b64: z.string().min(1).describe("standard base64") }),
    z.object({
      path: z
        .string()
        .min(1)
        .describe("filesystem path, read by the stdio adapter"),
    }),
  ])
  .describe("Bytes as base64, or a path the local server reads");

export const TrustRootSchema = z
  .discriminatedUnion("root", [
    z
      .object({
        root: z.literal("genesis"),
        genesis: BytesInputSchema,
      })
      .describe(
        "Trust the log's genesis document. Answers sealing and attribution; " +
          "cannot answer split-view.",
      ),
    z
      .object({
        root: z.literal("known-log-key"),
        keyXy: BytesInputSchema.describe("raw 64-byte P-256 x||y"),
      })
      .describe(
        "Trust a log owner key you obtained out of band. Same questions as " +
          "genesis; the key-to-log binding is asserted, not proven.",
      ),
    z
      .object({
        root: z.literal("known-accumulator"),
        accumulator: BytesInputSchema.describe(
          "encodeKnownAccumulator snapshot bytes",
        ),
        massif: BytesInputSchema.optional(),
        consistencyProof: BytesInputSchema.optional(),
      })
      .describe(
        "Trust an on-chain accumulator snapshot you hold. The only root that " +
          "answers split-view. Checks no signature locally — the anchor is the " +
          "authority.",
      ),
    z
      .object({
        root: z.literal("checkpoint-chain"),
        checkpoints: z
          .array(BytesInputSchema)
          .min(1)
          .describe("retained .sth objects in ascending massif order"),
        genesis: BytesInputSchema.optional(),
        keyXy: BytesInputSchema.optional(),
      })
      .describe(
        "Fold a retained checkpoint chain and match any authenticated link. " +
          "Answers split-view. Needs genesis or keyXy to root the first link.",
      ),
  ])
  .describe("Which anchor you are willing to trust (plan-2609-02 D2/D3)");

/* ---------------------------- inputs ---------------------------- */

export const verifyReceiptInputShape = {
  receipt: BytesInputSchema.describe("the COSE receipt"),
  payload: BytesInputSchema.describe(
    "the EXACT registered payload bytes whose SHA-256 is the leaf ContentHash",
  ),
  entryId: z
    .string()
    .regex(/^[0-9a-f]{32}$/)
    .describe("32 lowercase hex: idtimestamp_be8 || mmrIndex_be8"),
  trust: TrustRootSchema,
};

export const verifyGrantReceiptInputShape = {
  receipt: BytesInputSchema.describe("the COSE receipt"),
  committedGrant: BytesInputSchema.describe(
    "Forestrie-Grant COSE Sign1, or raw grant payload CBOR",
  ),
  entryId: z
    .string()
    .regex(/^[0-9a-f]{32}$/)
    .optional()
    .describe("required when committedGrant is a raw payload"),
  trust: TrustRootSchema,
};

export const decodeReceiptInputShape = {
  receipt: BytesInputSchema.describe("the COSE receipt to render"),
};

/* ---------------------------- outputs --------------------------- */

const StageRowSchema = z.object({
  stage: z.enum(["parse", "signature", "inclusion", "binding"]),
  status: z.enum(["ok", "failed", "skipped"]),
  reason: z.string().optional(),
});

const QuestionAnswerSchema = z.object({
  status: z.enum(["ok", "failed", "not_answered_by_this_root"]),
  note: z.string(),
});

const AnchorSchema = z.object({
  anchored: z.boolean(),
  anchoredSize: z.string(),
  peakCount: z.number(),
  matchedPeak: z.number().nullable(),
  reason: z.string().optional(),
  blockNumber: z.string().optional(),
  blockHash: z.string().optional(),
  univocity: z.string().optional(),
  logId: z.string().optional(),
  linkCount: z.number().optional(),
  matchedLinkSize: z.string().optional(),
});

/**
 * The D3 result. `stages` and `questions` are BOTH here on purpose: the first
 * is the mechanical verdict, the second is what that verdict is evidence for.
 * A client that renders only `ok` is using this tool wrong, and the
 * descriptions say so.
 */
export const verifyOutputShape = {
  ok: z.boolean(),
  root: z.enum([
    "genesis",
    "known-log-key",
    "known-accumulator",
    "checkpoint-chain",
  ]),
  stage: z.enum(["parse", "signature", "inclusion", "binding"]),
  reason: z.string().optional(),
  stages: z
    .array(StageRowSchema)
    .describe("the mechanical stages, exactly the reference CLI's contract"),
  anchor: AnchorSchema.optional(),
  questions: z
    .object({
      "split-view": QuestionAnswerSchema,
      sealing: QuestionAnswerSchema,
      "append-authority": QuestionAnswerSchema,
      attribution: QuestionAnswerSchema,
    })
    .describe(
      "the four trust questions. 'not_answered_by_this_root' is a real " +
        "answer and must be shown to the user, never collapsed into a pass.",
    ),
  diagnostics: z
    .array(z.object({ code: z.string(), message: z.string() }))
    .describe("named notes about what the arithmetic could not separate"),
  verifier: z.object({
    package: z.string(),
    version: z.string(),
    receiptVerify: z.string(),
  }),
};

/**
 * The decode result is a rendering, not a verdict, and its interior is a
 * faithful echo of whatever CBOR was in the receipt — including labels no
 * registry knows. Pinning every field would make the schema a second, worse
 * copy of the CBOR spec and would reject valid receipts carrying new labels.
 * So the summary fields are typed and the rest is passthrough.
 */
export const decodeOutputShape = {
  byteLength: z.number(),
  tag: z.number().nullable(),
  protected: z.looseObject({ byteLength: z.number() }),
  unprotected: z.looseObject({}),
  payload: z.looseObject({ detached: z.boolean() }),
  signature: z.object({ byteLength: z.number(), hex: z.string() }),
  inclusion: z.object({
    mmrIndex: z.string(),
    pathLength: z.number(),
    path: z.array(z.string()),
    peakHex: z.string().nullable(),
    peakSource: z.string(),
  }),
};
