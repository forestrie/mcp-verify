/**
 * CBOR → JSON rendering of a receipt. No verification, no network, no files.
 *
 * Everything on the Forestrie wire is CBOR, and nothing published renders it.
 * `@forestrie/receipt-verify` exports `parseReceipt`, which does the
 * load-bearing structural parse (COSE_Sign1 shape, tag-18 tolerance, payload
 * rules, header 396 inclusion proof) but leaves the protected header as the
 * opaque signed bstr it must be. This module turns that result into a display
 * model: protected-header contents, named labels, JSON-safe values.
 *
 * ## This stays a local renderer — delegating to a dependency was tried and reverted
 *
 * `parseReceipt` from `@forestrie/receipt-verify`, and
 * `decodeCborDeterministic` / `coseUnprotectedToMap` / `decodeCoseSign1` /
 * `CborTag` from `@forestrie/encoding@0.7.0`, are the only dependencies. The
 * label tables below are kept in sync with the authoritative registry:
 * [forestrie/protocol `spec/label-registry.md`](https://github.com/forestrie/protocol/blob/main/spec/label-registry.md).
 *
 * `@forestrie/forestrie-cli` publishes this same renderer at a pure subpath
 * export, `@forestrie/forestrie-cli/decode-receipt` — name- and
 * shape-compatible with the public surface below, so delegating to it is a
 * one-line import change (plan-2609-02 step P5.5). It has been tried twice
 * and reverted twice, for two different reasons.
 *
 * At `0.8.0` the CLI's registry did not carry two forestrie private-use
 * codepoints real receipts use — COSE algorithm `-65800`
 * (`ALG_ES256_WEBAUTHN`) and header label `-65801` (the session-key
 * endorsement, `TBD2`) — so delegating silently turned their `name` into
 * `null`. `0.8.1` fixed exactly that (forestrie-cli#54) and added header
 * label `-65800` (the WebAuthn assertion envelope) and `-66535` (the
 * on-chain delegation proof) besides. Those last two are not mirrored below
 * — they name codepoints this table has never named, so adopting them is an
 * output change on its own merits, to be made deliberately and not as a side
 * effect of a dependency bump.
 *
 * It still does not match. `0.8.1` names those codepoints with **different
 * text** to the tables below, and that text is rendered output, not
 * commentary — `note` reaches `DecodedHeaderEntry.note`, and `ALG_NAMES`'
 * value reaches the `alg.name` field:
 *
 *   - `ALG_NAMES[-65800]`: here `"ES256-WebAuthn (forestrie private-use)"`;
 *     the CLI appends `"; delegation proofs and certificates only, never
 *     checkpoint-signing"`.
 *   - `HEADER_LABELS[-65801].note`: here `"forestrie private-use"`; the CLI
 *     says `"forestrie TBD2: the endorsement COSE_Sign1, embedded as a bstr
 *     (unprotected, leaf-admission-and-session-endorsement.md)"`. The `name`
 *     agrees.
 *
 * Neither is wrong — the CLI's is arguably better — but adopting it changes
 * what `decode_receipt` prints, which is a product decision and not a
 * dependency bump. As before, no gate catches it on its own: no fixture here
 * carries either codepoint, so `check:encoding-single-copy`,
 * `check:browser-safe` and the differential comparison all stay green. The
 * two tests in `test/core/decode-receipt.test.ts` assert these strings
 * directly against the tables below, which is why the second attempt was
 * caught by the gate rather than by review. **Do not loosen them to make a
 * delegation pass** — that would ship the output change silently, which is
 * the thing they exist to prevent.
 *
 * **Revisit delegating once the two tables agree textually.** The right fix
 * is upstream of both: settle the wording in the registry
 * ([forestrie/protocol `spec/label-registry.md`](https://github.com/forestrie/protocol/blob/main/spec/label-registry.md)),
 * land it in `forestrie-cli`, then adopt the strings here in a change that
 * says it is changing rendered output — after which this file becomes the
 * re-export it was always meant to be. The checklist for that change is in
 * `AGENTS.md`.
 *
 * Note also what delegating costs: the differential test's decode row
 * compares this renderer against the CLI's. Delegate, and both sides run the
 * same code and the row stops being evidence. See
 * `docs/differential-test.md`.
 *
 * ## One deliberate behavioural difference
 *
 * The reference renderer decodes the protected header with its own lenient
 * CBOR reader. This one uses `decodeCborDeterministic`, which rejects
 * indefinite lengths, floats, non-canonical encodings and trailing bytes. A
 * receipt whose protected header is not RFC 8949 §4.2 canonical renders in the
 * CLI and is refused here. That is the right way round for a tamper-evidence
 * tool — the signed bytes are supposed to be canonical, and quietly rendering
 * bytes the verifier would reject is how a decoder becomes misleading.
 */
import { parseReceipt } from "@forestrie/receipt-verify";
import {
  CborTag,
  coseUnprotectedToMap,
  decodeCborDeterministic,
  decodeCoseSign1,
} from "@forestrie/encoding";

/* ------------------------------------------------------------------ *
 * Label registry. Naming only: decoding never requires a label to be
 * known, and an unknown label is always shown raw, never dropped.
 *
 * Sources: RFC 9052 (COSE headers), RFC 9597 (CWT claims header 15),
 * RFC 8392 (CWT claim keys), RFC 8747 (cnf),
 * draft-ietf-cose-merkle-tree-proofs (395 vds / 396 verifiable proofs),
 * and the forestrie private-use labels.
 * ------------------------------------------------------------------ */

/** CBOR tag for COSE_Sign1 (RFC 9052 §2). */
export const COSE_SIGN1_TAG = 18;
/** Verifiable data structure, protected (draft-ietf-cose-merkle-tree-proofs). */
export const VDS_LABEL = 395;
/** Verifiable proofs, unprotected (draft-ietf-cose-merkle-tree-proofs). */
export const VERIFIABLE_PROOFS_LABEL = 396;
/** CWT claims in a COSE header (RFC 9597). */
export const CWT_CLAIMS_LABEL = 15;
/** Custodian per-log delegation certificate, a nested COSE_Sign1. */
export const DELEGATION_CERT_LABEL = 1000;
/** Pre-signed peak inclusion receipts on a checkpoint. */
export const SEAL_PEAK_RECEIPTS_LABEL = -65931;

/** Inclusion proofs key inside header 396. */
export const PROOFS_INCLUSION_KEY = -1;
/** Consistency proofs key inside header 396. */
export const PROOFS_CONSISTENCY_KEY = -2;

export type LabelInfo = { name: string; note?: string };

export const HEADER_LABELS: ReadonlyMap<number, LabelInfo> = new Map([
  [1, { name: "alg" }],
  [2, { name: "crit" }],
  [3, { name: "content type" }],
  [4, { name: "kid" }],
  [5, { name: "IV" }],
  [6, { name: "partial IV" }],
  [CWT_CLAIMS_LABEL, { name: "CWT claims", note: "RFC 9597" }],
  [
    VDS_LABEL,
    { name: "verifiable data structure", note: "COSE receipts (draft)" },
  ],
  [
    VERIFIABLE_PROOFS_LABEL,
    { name: "verifiable proofs", note: "COSE receipts (draft)" },
  ],
  [
    DELEGATION_CERT_LABEL,
    {
      name: "delegation certificate",
      note: "forestrie: Custodian per-log delegation (nested COSE_Sign1)",
    },
  ],
  [-65537, { name: "idtimestamp", note: "forestrie private-use" }],
  [-65538, { name: "forestrie grant v0", note: "forestrie private-use" }],
  [
    SEAL_PEAK_RECEIPTS_LABEL,
    {
      name: "pre-signed peak receipts",
      note: "forestrie SealPeakReceiptsLabel (checkpoint header)",
    },
  ],
  [-65801, { name: "session key endorsement", note: "forestrie private-use" }],
  [-68009, { name: "forest genesis version", note: "forestrie private-use" }],
  [-68011, { name: "univocity address", note: "forestrie private-use" }],
  [-68013, { name: "chain id", note: "forestrie private-use" }],
  [-68014, { name: "forest genesis alg", note: "forestrie private-use" }],
  [-68015, { name: "bootstrap key", note: "forestrie private-use" }],
]);

export const ALG_NAMES: ReadonlyMap<number, string> = new Map([
  [-7, "ES256 (ECDSA P-256 + SHA-256)"],
  [-8, "EdDSA"],
  [-35, "ES384"],
  [-36, "ES512"],
  [-65799, "KS256 (secp256k1 + Keccak-256, forestrie private-use)"],
  [-65800, "ES256-WebAuthn (forestrie private-use)"],
]);

/**
 * Verifiable data structure ids. 3 is NOT a registered codepoint:
 * draft-bryce-cose-receipts-mmr-profile requests TBD, and 3 is only the value
 * the test fixtures use. Render it as the draft's unregistered codepoint,
 * never as registry fact.
 */
export const VDS_NAMES: ReadonlyMap<number, string> = new Map([
  [1, "RFC9162_SHA256 (Certificate Transparency)"],
  [2, "CCF_LEDGER_SHA256"],
  [3, "MMR profile (draft-bryce, codepoint TBD)"],
]);

export const CWT_CLAIM_NAMES: ReadonlyMap<number, string> = new Map([
  [1, "iss"],
  [2, "sub"],
  [3, "aud"],
  [4, "exp"],
  [5, "nbf"],
  [6, "iat"],
  [7, "cti"],
  [8, "cnf (confirmation / ephemeral key)"],
]);

export const COSE_KEY_PARAM_NAMES: ReadonlyMap<number, string> = new Map([
  [1, "kty"],
  [2, "kid"],
  [3, "alg"],
  [-1, "crv"],
  [-2, "x"],
  [-3, "y"],
]);

/** Keys inside header 396 (draft-ietf-cose-merkle-tree-proofs). */
export const PROOF_KIND_NAMES: ReadonlyMap<number, string> = new Map([
  [PROOFS_INCLUSION_KEY, "inclusion proofs"],
  [PROOFS_CONSISTENCY_KEY, "consistency proofs"],
]);

/** Look up a header label name; null when unknown (the caller shows it raw). */
export function headerLabelInfo(label: number): LabelInfo | null {
  return HEADER_LABELS.get(label) ?? null;
}

/* ------------------------------------------------------------------ *
 * Display model
 * ------------------------------------------------------------------ */

/** Which parse stage rejected the input. */
export type DecodeReceiptStage =
  | "input"
  | "envelope"
  | "cose-sign1"
  | "payload"
  | "protected-header"
  | "inclusion-proof";

export class DecodeReceiptError extends Error {
  readonly stage: DecodeReceiptStage;
  constructor(stage: DecodeReceiptStage, message: string) {
    super(message);
    this.name = "DecodeReceiptError";
    this.stage = stage;
  }
}

/** JSON-safe value: bytes become `h'…'` diagnostic-notation strings. */
export type Json =
  string | number | boolean | null | Json[] | { [key: string]: Json };

export type DecodedHeaderEntry = {
  /** Raw CBOR label (int, or string for text keys). */
  label: number | string;
  /** Registry name, or null when unknown (the value is still shown). */
  name: string | null;
  note: string | null;
  value: Json;
};

export type DecodedClaim = {
  key: number | string;
  name: string | null;
  value: Json;
};

export type DecodedReceipt = {
  byteLength: number;
  /** Outer CBOR tag (18 for COSE_Sign1) or null when untagged. */
  tag: number | null;
  protected: {
    byteLength: number;
    alg: { value: number; name: string | null } | null;
    kid: { hex: string; byteLength: number } | { text: string } | null;
    vds: { value: number; name: string | null } | null;
    cwtClaims: DecodedClaim[] | null;
    entries: DecodedHeaderEntry[];
  };
  unprotected: {
    entries: DecodedHeaderEntry[];
    delegation: { byteLength: number; nestedCoseSign1: boolean } | null;
    peakReceipts: { count: number } | null;
  };
  payload:
    { detached: true } | { detached: false; byteLength: number; hex: string };
  signature: { byteLength: number; hex: string };
  /** MMR inclusion proof summary (header 396, key -1). */
  inclusion: {
    mmrIndex: string;
    pathLength: number;
    path: string[];
    /** 32-byte peak when the payload is attached; null when detached. */
    peakHex: string | null;
    peakSource: "payload" | "derived at verify time (detached payload)";
  };
};

const HEX = Array.from({ length: 256 }, (_, i) =>
  i.toString(16).padStart(2, "0"),
);

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += HEX[b];
  return out;
}

/** Any decoded CBOR value → JSON-safe display form. */
export function toJson(value: unknown): Json {
  if (value === null || value === undefined) return null;
  if (typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : String(value);
  }
  if (typeof value === "bigint") {
    return value >= BigInt(Number.MIN_SAFE_INTEGER) &&
      value <= BigInt(Number.MAX_SAFE_INTEGER)
      ? Number(value)
      : value.toString(10);
  }
  if (value instanceof Uint8Array) return `h'${bytesToHex(value)}'`;
  if (Array.isArray(value)) return value.map(toJson);
  if (value instanceof Map) {
    const out: { [key: string]: Json } = {};
    for (const [k, v] of value) out[String(toJson(k))] = toJson(v);
    return out;
  }
  if (value instanceof CborTag) {
    return { tag: value.tag, value: toJson(value.value) };
  }
  if (typeof value === "object") {
    const out: { [key: string]: Json } = {};
    for (const [k, v] of Object.entries(value)) out[k] = toJson(v);
    return out;
  }
  return String(value);
}

function numericLabel(key: unknown): number | string {
  if (typeof key === "number") return key;
  if (typeof key === "bigint") return Number(key);
  const n = Number(key);
  return Number.isFinite(n) ? n : String(key);
}

function headerEntry(key: unknown, value: unknown): DecodedHeaderEntry {
  const label = numericLabel(key);
  const info =
    typeof label === "number" ? (HEADER_LABELS.get(label) ?? null) : null;
  return {
    label,
    name: info?.name ?? null,
    note: info?.note ?? null,
    value: toJson(value),
  };
}

function decodeCwtClaims(claims: unknown): DecodedClaim[] {
  if (!(claims instanceof Map)) {
    return [{ key: "(malformed)", name: null, value: toJson(claims) }];
  }
  const out: DecodedClaim[] = [];
  for (const [k, v] of claims) {
    const key = numericLabel(k);
    const name =
      typeof key === "number" ? (CWT_CLAIM_NAMES.get(key) ?? null) : null;
    // cnf (8) carries key material — name the COSE_Key params for the reader.
    if (key === 8 && v instanceof Map) {
      const cnf: { [param: string]: Json } = {};
      for (const [pk, pv] of v) {
        const paramKey = numericLabel(pk);
        const paramName =
          typeof paramKey === "number"
            ? COSE_KEY_PARAM_NAMES.get(paramKey)
            : undefined;
        cnf[
          paramName !== undefined
            ? `${paramKey} (${paramName})`
            : String(paramKey)
        ] = toJson(pv);
      }
      out.push({ key, name, value: cnf });
      continue;
    }
    out.push({ key, name, value: toJson(v) });
  }
  return out;
}

/** Classify a `parseReceipt` failure by the stage that rejected the input. */
function classifyParseError(error: unknown): DecodeReceiptError {
  const message = error instanceof Error ? error.message : String(error);
  if (/COSE Sign1/i.test(message)) {
    return new DecodeReceiptError("cose-sign1", message);
  }
  if (/payload/i.test(message)) {
    return new DecodeReceiptError("payload", message);
  }
  if (/header 396|proof/i.test(message)) {
    return new DecodeReceiptError("inclusion-proof", message);
  }
  return new DecodeReceiptError("envelope", message);
}

/**
 * Decode receipt bytes to the display model.
 *
 * Only receipts: a checkpoint (`.sth`) carries a consistency proof at header
 * 396 key -2 rather than an inclusion proof at key -1, and `parseReceipt`
 * rejects it. That surfaces here as a `DecodeReceiptError` with
 * `stage: "inclusion-proof"`, which is honest — this is a receipt decoder.
 *
 * @throws {DecodeReceiptError} naming the parse stage on malformed input
 */
export function decodeReceipt(receiptBytes: Uint8Array): DecodedReceipt {
  if (receiptBytes.length === 0) {
    throw new DecodeReceiptError("input", "receipt is empty (0 bytes)");
  }

  // Tag tolerance: parseReceipt accepts tagged and untagged; record which we
  // got. Tag 18 with a 1-byte argument encodes as the initial byte 0xd2.
  const tag = receiptBytes[0] === 0xd2 ? COSE_SIGN1_TAG : null;

  let parsed: ReturnType<typeof parseReceipt>;
  try {
    parsed = parseReceipt(receiptBytes);
  } catch (error) {
    throw classifyParseError(error);
  }
  const [protectedBstr, unprotectedRaw, payload, signature] = parsed.coseSign1;

  // The protected header is the SIGNED bytes; parseReceipt keeps it opaque
  // deliberately. Open it here for display only — nothing downstream of this
  // function feeds a verification decision.
  let protectedMap: Map<unknown, unknown>;
  try {
    const decoded = decodeCborDeterministic(protectedBstr);
    if (!(decoded instanceof Map)) {
      throw new Error(
        `expected a CBOR map, got ${decoded === null ? "null" : typeof decoded}`,
      );
    }
    protectedMap = decoded;
  } catch (error) {
    throw new DecodeReceiptError(
      "protected-header",
      `protected header is not a canonical CBOR map: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  let alg: DecodedReceipt["protected"]["alg"] = null;
  let kid: DecodedReceipt["protected"]["kid"] = null;
  let vds: DecodedReceipt["protected"]["vds"] = null;
  let cwtClaims: DecodedClaim[] | null = null;
  const protectedEntries: DecodedHeaderEntry[] = [];
  for (const [k, v] of protectedMap) {
    protectedEntries.push(headerEntry(k, v));
    const label = numericLabel(k);
    if (label === 1 && (typeof v === "number" || typeof v === "bigint")) {
      const value = Number(v);
      alg = { value, name: ALG_NAMES.get(value) ?? null };
    } else if (label === 4) {
      if (v instanceof Uint8Array) {
        kid = { hex: bytesToHex(v), byteLength: v.length };
      } else if (typeof v === "string") {
        kid = { text: v };
      }
    } else if (
      label === VDS_LABEL &&
      (typeof v === "number" || typeof v === "bigint")
    ) {
      const value = Number(v);
      vds = { value, name: VDS_NAMES.get(value) ?? null };
    } else if (label === CWT_CLAIMS_LABEL) {
      cwtClaims = decodeCwtClaims(v);
    }
  }

  const unprotectedMap = coseUnprotectedToMap(unprotectedRaw);
  const unprotectedEntries: DecodedHeaderEntry[] = [];
  let delegation: DecodedReceipt["unprotected"]["delegation"] = null;
  let peakReceipts: DecodedReceipt["unprotected"]["peakReceipts"] = null;
  for (const [label, value] of unprotectedMap) {
    unprotectedEntries.push(headerEntry(label, value));
    if (label === DELEGATION_CERT_LABEL && value instanceof Uint8Array) {
      delegation = {
        byteLength: value.length,
        nestedCoseSign1: decodeCoseSign1(value) !== null,
      };
    } else if (label === SEAL_PEAK_RECEIPTS_LABEL && Array.isArray(value)) {
      peakReceipts = { count: value.length };
    }
  }

  const path = parsed.proof.path.map(bytesToHex);
  const peakHex =
    parsed.explicitPeak !== null ? bytesToHex(parsed.explicitPeak) : null;

  return {
    byteLength: receiptBytes.length,
    tag,
    protected: {
      byteLength: protectedBstr.length,
      alg,
      kid,
      vds,
      cwtClaims,
      entries: protectedEntries,
    },
    unprotected: {
      entries: unprotectedEntries,
      delegation,
      peakReceipts,
    },
    payload:
      payload instanceof Uint8Array
        ? {
            detached: false,
            byteLength: payload.length,
            hex: bytesToHex(payload),
          }
        : { detached: true },
    signature: { byteLength: signature.length, hex: bytesToHex(signature) },
    inclusion: {
      // parseReceipt always sets mmrIndex; merklelog's Proof marks it optional.
      mmrIndex: (parsed.proof.mmrIndex ?? 0n).toString(10),
      pathLength: path.length,
      path,
      peakHex,
      peakSource:
        peakHex !== null
          ? "payload"
          : "derived at verify time (detached payload)",
    },
  };
}
