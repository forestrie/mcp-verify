/**
 * zod input schemas and `outputSchema`s for the four tools.
 *
 * O2, resolved against a live SDK rather than guessed:
 * `@modelcontextprotocol/sdk@1.30.0` accepts zod-4 schemas directly for both
 * `inputSchema` and `outputSchema` and emits draft-07 JSON Schema itself — no
 * `z.toJSONSchema()` at the call site. It wants a **raw shape**
 * (`{ key: ZodType }`) rather than a `ZodObject`, which is also what types the
 * handler's argument correctly, so composite types live as property values.
 * test/node/mcp-smoke.test.ts keeps it true.
 */
import { z } from "zod";

/** The accepted shapes, named in every byte field's description and in the
 *  validation error for a wrong shape — the SDK renders a plain `z.union`
 *  failure as "Invalid input at <field>", which tells a caller nothing
 *  about what was wanted. `base64` is `@forestrie/mcp-resolve`'s original
 *  name for the same thing and is accepted here permanently. */
export const BYTES_SHAPES =
  "{b64: <standard base64>} (base64 is accepted as an alias), or {path: <a file the local server reads>}";

/** Bytes cross the MCP boundary as base64; stdio additionally accepts a path. */
export const BytesInputSchema = z
  .union(
    [
      z.object({ b64: z.string().min(1).describe("standard base64") }),
      z.object({
        base64: z.string().min(1).describe("standard base64 (alias of b64)"),
      }),
      z.object({
        path: z
          .string()
          .min(1)
          .describe("filesystem path, read by the stdio adapter"),
      }),
    ],
    { error: `expected bytes as ${BYTES_SHAPES}` },
  )
  .describe(`Bytes as ${BYTES_SHAPES}`);

/** A byte field whose description names the accepted shapes as well as
 *  what the bytes are — a field-level `.describe()` replaces the union's
 *  own text in the advertised schema, so the shapes must be restated
 *  (previously they survived only on `trust.genesis`, the one field
 *  without its own description). */
export function bytesInput(what: string) {
  return BytesInputSchema.describe(`${what} — ${BYTES_SHAPES}`);
}

export const TrustRootSchema = z
  .discriminatedUnion(
    "root",
    [
      z
        .object({
          root: z.literal("genesis"),
          genesis: bytesInput("the forest's genesis document"),
        })
        .describe(
          "Trust the log's genesis document. Answers sealing and attribution; " +
            "cannot answer split-view.",
        ),
      z
        .object({
          root: z.literal("known-log-key"),
          keyXy: bytesInput(
            "raw 64-byte P-256 x||y (ES256 owner key)",
          ).optional(),
          ks256Address: z
            .string()
            .regex(
              /^0x[0-9a-fA-F]{40}$/,
              "expected 0x followed by 40 hex digits",
            )
            .optional()
            .describe(
              "KS256 (secp256k1/keccak) owner address, 0x + 40 hex: an EOA " +
                "or a contract (Safe). Give exactly one of keyXy or ks256Address.",
            ),
          forestGenesis: bytesInput(
            "the forest's genesis document, same encoding as the genesis " +
              "root's `genesis` field. Read ONLY for the chain id a " +
              "ks256Attestation must match; it supplies no trust keys",
          ).optional(),
        })
        .refine(
          (v) => (v.keyXy === undefined) !== (v.ks256Address === undefined),
          {
            message:
              "known-log-key takes exactly one of keyXy (64-byte P-256 x||y) or ks256Address (0x + 40 hex)",
          },
        )
        .describe(
          "Trust a log owner key you obtained out of band: a 64-byte P-256 " +
            "key (keyXy) or a 20-byte KS256 address (ks256Address). Same " +
            "questions as genesis; the key-to-log binding is ASSERTED by you, " +
            "not proven — an address in particular proves nothing about " +
            "which log it owns. A contract (Safe) address needs " +
            "ks256Attestation on the tool call to verify offline.",
        ),
      z
        .object({
          root: z.literal("known-accumulator"),
          accumulator: bytesInput("encodeKnownAccumulator snapshot bytes"),
          massif: BytesInputSchema.optional(),
          consistencyProof: BytesInputSchema.optional(),
        })
        .describe(
          "Trust an on-chain accumulator snapshot you hold. The only root that " +
            "answers split-view. Checks no signature locally — the anchor is the " +
            "authority. The peak is recomputed from leaf + inclusion path; a " +
            "peak attached to the receipt is checked against it, never trusted.",
        ),
      z
        .object({
          root: z.literal("checkpoint-chain"),
          checkpoints: z
            .array(BytesInputSchema)
            .min(1)
            .describe(
              `retained .sth objects in ascending massif order, each ${BYTES_SHAPES}`,
            ),
          genesis: BytesInputSchema.optional(),
          keyXy: BytesInputSchema.optional(),
        })
        .describe(
          "Fold a retained checkpoint chain and match any authenticated link. " +
            "Answers split-view. Needs genesis or keyXy to root the first link. " +
            "Each link's delegation certificate limits are enforced: a link " +
            "signed beyond the certificate's mmrEnd, or below its mmrStart, " +
            "fails delegation_out_of_range, " +
            "and a link covering the receipt's leaf signed under a certificate " +
            "that had expired when the leaf was sequenced fails " +
            "delegation_expired (never wall-clock). A KS256 contract (Safe) " +
            "genesis root takes ks256Attestation on the tool call (one per " +
            "delegation certificate: several in ks256Attestations). Failures " +
            "carry the typed reason, with stage/detail/failedLink naming the link.",
        ),
    ],
    {
      error:
        "trust.root must be one of genesis, known-log-key, known-accumulator, checkpoint-chain",
    },
  )
  .describe("Which anchor you are willing to trust");

/** The four tool names, in registration order — the one list `server.ts`
 *  registers from and `cli.ts`'s `--help` prints, so the two cannot drift.
 *  `test/node/help.test.ts` asserts `--help` names exactly what
 *  `tools/list` returns. */
export const TOOL_NAMES = [
  "verify_receipt",
  "verify_grant_receipt",
  "decode_receipt",
  "verify_self",
] as const;
export type ToolName = (typeof TOOL_NAMES)[number];

/* ---------------------------- inputs ---------------------------- */

/** Shared by verify_receipt and verify_grant_receipt. */
const ks256AttestationInput = bytesInput(
  "ERC-1271 attestation artifact (encodeKs256Attestation CBOR) for a KS256 " +
    "CONTRACT root. Fetched elsewhere — this server never touches the " +
    "network: use mcp-resolve's `fetch_ks256_attestation` tool or " +
    "forestrie-cli's `fetch-ks256-attestation`. With it a contract-rooted " +
    "delegation verifies as valid under the contract's signers at the " +
    "attested block. Usable with the genesis, known-log-key and " +
    "checkpoint-chain roots (checkpoint-chain also needs trust.genesis for " +
    "the forest chain id; one attestation binds one certificate, so a chain " +
    "whose links were signed under several certificates needs one " +
    "attestation per certificate: give them in ks256Attestations). Not " +
    "with known-accumulator. " +
    "Trust: the attestation is unsigned and only as good as whoever fetched it; " +
    "accept one only from a party you would trust to read the chain for you",
).optional();

/**
 * Several attestations, for a Safe that rotated its delegate: one
 * certificate per delegate, one attestation per certificate. Added ALONGSIDE
 * the singular field (which keeps working) rather than widening it, so
 * existing callers and schemas are untouched. When both are given they are
 * combined, the singular first.
 */
const ks256AttestationsInput = z
  .array(BytesInputSchema)
  .min(1)
  .describe(
    "Several ERC-1271 attestations (each encodeKs256Attestation CBOR, " +
      `${BYTES_SHAPES}) for a KS256 CONTRACT root that signed more than one ` +
      "delegation certificate (a Safe that rotated its delegate). Each " +
      "certificate takes the attestation whose digest and signature hash are " +
      "its own. Combined with ks256Attestation when both are given. Every " +
      "attestation is reported in the result as used or unused with a reason " +
      "(ks256Attestations): none is silently ignored. Same roots and trust " +
      "caveats as ks256Attestation.",
  )
  .optional();

export const verifyReceiptInputShape = {
  receipt: bytesInput("the COSE receipt"),
  payload: bytesInput(
    "the EXACT registered payload bytes whose SHA-256 is the leaf ContentHash",
  ),
  entryId: z
    .string()
    .regex(/^[0-9a-f]{32}$/)
    .describe("32 lowercase hex: idtimestamp_be8 || mmrIndex_be8"),
  trust: TrustRootSchema,
  ks256Attestation: ks256AttestationInput,
  ks256Attestations: ks256AttestationsInput,
};

export const verifyGrantReceiptInputShape = {
  receipt: bytesInput("the COSE receipt"),
  committedGrant: bytesInput(
    "Forestrie-Grant COSE Sign1, or raw grant payload CBOR",
  ),
  entryId: z
    .string()
    .regex(/^[0-9a-f]{32}$/)
    .optional()
    .describe("required when committedGrant is a raw payload"),
  trust: TrustRootSchema,
  ks256Attestation: ks256AttestationInput,
  ks256Attestations: ks256AttestationsInput,
};

export const decodeReceiptInputShape = {
  receipt: bytesInput("the COSE receipt to render"),
};

/**
 * `verify_self`'s trust root is narrower than `TrustRootSchema`: the
 * `known-log-key` and `genesis` bytes come from the bundle itself
 * (`fixtures/self/log-key.xy.b64`, `genesis.cbor`) rather than from the
 * caller, since the whole point of this tool is verifying THIS package's own
 * bundle. Only `known-accumulator` needs caller-supplied bytes — the bundle
 * ships no accumulator snapshot.
 */
export const VerifySelfRootSchema = z
  .discriminatedUnion("root", [
    z
      .object({ root: z.literal("known-log-key") })
      .describe(
        "the default: the bundled log owner key, fixtures/self/log-key.xy.b64",
      ),
    z
      .object({ root: z.literal("genesis") })
      .describe(
        "the bundled forest genesis document. Reports delegation_invalid " +
          "for this receipt today: the publications log is a grandchild of " +
          "the forest root and nothing walks the grant chain that far yet " +
          "(docs/self-registration.md).",
      ),
    z
      .object({
        root: z.literal("known-accumulator"),
        accumulator: bytesInput("encodeKnownAccumulator snapshot bytes"),
        massif: BytesInputSchema.optional(),
        consistencyProof: BytesInputSchema.optional(),
      })
      .describe(
        "a caller-supplied accumulator snapshot. The only root here that " +
          "answers split-view.",
      ),
  ])
  .describe(
    "Which trust root to run verify_self under. Defaults to known-log-key " +
      "with the bundled key, not genesis — see docs/self-registration.md.",
  );

export const verifySelfInputShape = {
  root: VerifySelfRootSchema.optional(),
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

const Ks256AttestationReportSchema = z
  .object({
    chainId: z.string(),
    blockNumber: z.string(),
    blockHash: z.string(),
    address: z.string(),
  })
  .describe(
    "present only when a supplied ERC-1271 attestation was needed for the run to pass " +
      "(the first one, when several were): a contract root is valid under its " +
      "signers at THIS block only",
  );

const Ks256AttestationsReportSchema = z
  .object({
    used: z.array(
      z.object({
        index: z.number(),
        digest: z.string(),
        links: z.array(z.number()).optional(),
        chainId: z.string(),
        blockNumber: z.string(),
        blockHash: z.string(),
        address: z.string(),
      }),
    ),
    rejected: z.array(
      z.object({
        index: z.number(),
        digest: z.string(),
        links: z.array(z.number()),
      }),
    ),
    unused: z.array(
      z.object({ index: z.number(), digest: z.string(), reason: z.string() }),
    ),
  })
  .describe(
    "every supplied attestation, accounted for: used ones carried the run " +
      "(valid under the contract's signers at each named block only); unused " +
      "ones say why (not_needed, no_matching_certificate, duplicate, run_failed); rejected ones were tried for a link's certificate and refused. " +
      "Index is the position in the supplied list (ks256Attestation first, then ks256Attestations)",
  );

/**
 * The verify result. `stages` and `questions` are BOTH here on purpose: the first
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
  detail: z
    .string()
    .optional()
    .describe("checkpoint-chain: which link failed and why, in words"),
  failedLink: z
    .number()
    .optional()
    .describe("checkpoint-chain: index of the link a failure names"),
  ks256Attestation: Ks256AttestationReportSchema.optional(),
  ks256Attestations: Ks256AttestationsReportSchema.optional(),
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
 * `verify_self`'s result: the verify result above, plus what only this tool
 * checks — whether `statement.cose`'s signed payload is byte-for-byte the
 * `provenance.json` in the bundle, and whether that signature verifies under
 * the bundled log key. `provenance` is `null` when `provenance.json` did not
 * even parse as JSON, which a tampered bundle may produce.
 */
export const verifySelfOutputShape = {
  ...verifyOutputShape,
  self: z.object({
    provenance: z
      .object({
        name: z.string(),
        version: z.string(),
        gitCommit: z.string(),
        builtAt: z.string(),
      })
      .nullable(),
    statementSignature: z.enum(["ok", "failed"]),
    payloadMatchesProvenance: z.boolean(),
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
