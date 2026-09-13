/**
 * CBOR → JSON rendering of a receipt. No verification, no network, no files.
 *
 * Re-exported from `@forestrie/forestrie-cli`'s published library entry
 * (plan-2609-02 workstream P step P5.5). This used to be a fresh
 * implementation written over `@forestrie/receipt-verify` and
 * `@forestrie/encoding` directly, because `forestrie-cli` at v0.7.0 was
 * `private: true` with no importable surface. `@forestrie/forestrie-cli
 * @0.8.0` now publishes exactly this surface at the
 * `@forestrie/forestrie-cli/decode-receipt` subpath — runtime-neutral (no
 * `node:*`, no I/O), depending only on `@forestrie/receipt-verify` and
 * `@forestrie/encoding` — so this file is a one-line re-export instead of a
 * parallel implementation.
 *
 * Both gates that matter for this swap are asserted on every `pnpm test`:
 * `check:encoding-single-copy` (the CLI pins `@forestrie/encoding ^0.7.0`,
 * which dedupes to our exact `0.7.0`) and `check:browser-safe` (the subpath
 * bundles clean for `platform: "browser"`). The differential test
 * (`test/differential/differential.test.ts`, `decode_receipt vs
 * decode-receipt --json`) is what would catch the swap changing behaviour —
 * it still passes, though it is a weaker check now that both sides run the
 * same code (see the note below).
 *
 * ## One known change from the previous implementation
 *
 * The CLI's published label registry does not carry two forestrie
 * private-use codepoints this repo's fresh implementation used to know:
 * header label `-65801` ("session key endorsement") and algorithm `-65800`
 * ("ES256-WebAuthn"). Neither is exercised by any fixture in this repo's test
 * suite (golden, burial or self-bundle), so no test — including the
 * differential one, which now runs identical code on both sides for this
 * comparison — catches it. A receipt carrying either codepoint renders that
 * entry with `name: null` (still shown, per the "never drop an unknown
 * label" rule) instead of the named label. Tracked as a finding for
 * `forestrie-cli`, not fixed here: vendoring the two entries back into this
 * tree would recreate the fork this swap exists to retire.
 */
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
} from "@forestrie/forestrie-cli/decode-receipt";
export type {
  DecodedClaim,
  DecodedHeaderEntry,
  DecodedReceipt,
  DecodeReceiptStage,
  Json,
  LabelInfo,
} from "@forestrie/forestrie-cli/decode-receipt";
