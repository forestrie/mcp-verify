# Dependency surface — what was checked, and what it decided

Bootstrap step 6 of the project-structure plan asked for three unknowns to be
resolved against a real install before any design was committed to. This is
the record. Checked 2026-09-05 on node 22.14.0 / pnpm 10.6.5.

Re-run these checks whenever a pinned version moves; the answers below are
what the code is shaped around, not background reading.

## 1. `@forestrie/receipt-verify@1.0.0` — every named export is present

Read from the installed `node_modules/@forestrie/receipt-verify/dist/index.d.ts`.

| Export the plan names                               | Present | Notes                                                     |
| --------------------------------------------------- | ------- | --------------------------------------------------------- |
| `verifyReceiptOffline`                              | yes     | `{genesisCbor, receiptCbor, payload, idtimestampBe8}`     |
| `verifyReceiptOfflineWithKeys`                      | yes     | same minus `genesisCbor`, plus `trustKeys: CryptoKey[]`   |
| `verifyGrantReceiptOffline`                         | yes     | takes a **decoded** `Grant`, not grant bytes              |
| `verifyGrantReceiptOfflineWithKeys`                 | yes     |                                                           |
| `verifyReceiptOfflineAgainstKnownAccumulator`       | yes     | `{receiptCbor, idtimestampBe8, inner, accumulator, size}` |
| `verifyCheckpointChain`                             | yes     | `{checkpoints, verifySignature, accumulatorFrom?}`        |
| `parseReceipt`                                      | yes     |                                                           |
| `decodeTrustRootFromGenesis`                        | yes     | returns a `CryptoKey` for the ES256 case                  |
| `entryIdHexToIdtimestampBe8`                        | yes     |                                                           |
| `decodeKnownAccumulator` / `encodeKnownAccumulator` | yes     | plus `assertSnapshotBinding`                              |
| `ReceiptVerifyStage` (type)                         | yes     | `"parse" \| "signature" \| "inclusion" \| "binding"`      |

Also used here and worth naming: `grantCommitmentHashFromGrant`,
`importEs256PublicKeyFromGrantDataXy64`, `decodeForestrieGrantCose`,
`decodeGrantPayload`, `univocityLeafHash`, `accumulatorPayload`,
`computeCheckpointAccumulator`, `checkpointConsistencyProof`.

**Two shape facts that changed the design:**

1. There is **no** `verifyGrantReceiptOfflineAgainstKnownAccumulator`. The
   known-accumulator rung has exactly one entry point for both receipt kinds,
   and the caller supplies the leaf `inner` hash: `SHA-256(payload)` for a
   payload receipt, `grantCommitmentHashFromGrant(grant)` for a grant receipt.
   That is why `src/core/verify-receipt.ts` and
   `src/core/verify-grant-receipt.ts` differ only in how they produce `inner`
   and which offline verifier they call.
2. `verifyReceiptOfflineAgainstKnownAccumulator` **does not check any
   signature.** It parses, recomputes the peak from leaf + proof, and matches
   it against the caller's trusted accumulator. That is the correct shape for
   the rung — the accumulator _is_ the authority — and it is what makes the
   D3 separation real rather than cosmetic. See
   [trust-ladder.md](trust-ladder.md).

### The stage label this package does not control

`verifyReceiptOfflineAgainstKnownAccumulator` reports a peak mismatch as

```
{ ok: false, stage: "signature", reason: "peak_not_in_known_accumulator" }
```

— `stage: "signature"`, not `"inclusion"`, even though nothing about a
signature was evaluated. Same for `receipt_newer_than_known_accumulator`. This
is upstream's choice (`known-accumulator.ts`, both `return` statements), and
this package passes `stage`/`reason` through **verbatim** so that `stages[]`
stays byte-comparable with the reference CLI.

Consequence for the D3 table: the separation at the known-accumulator rung
shows up in the **reason** and in `questions["split-view"]`, not in the stage
name. The `accumulator_failure_reported_at_signature_stage` diagnostic says so
in the tool output rather than leaving a reader to guess. Filed as a finding
against `@forestrie/receipt-verify`.

## 2. `@forestrie/encoding@0.7.0` — `coseUnprotectedToMap` and `decodeCoseSign1` both still exported

```
$ grep -nE "coseUnprotectedToMap|decodeCoseSign1" node_modules/@forestrie/encoding/dist/index.d.ts
21:export { ..., decodeCoseSign1, ... } from "./verify-cose-sign1.js";
24:export { coseUnprotectedToMap } from "./cose-unprotected-map.js";
```

This was the blocking pre-check for O5, which asked whether to **vendor**
`forestrie-cli`'s `decode-receipt-{cbor,decode,labels}.ts` into this tree. Both
symbols are present, so vendoring would have compiled.

**It was not done anyway.** Vendoring buys differential exactness at the price
of a silent fork of 667 lines of someone else's source, and "the CLI is not on
npm" is not a good enough reason to take that trade. `src/core/decode-receipt.ts`
is written fresh over the published packages only — `parseReceipt` from
`@forestrie/receipt-verify`, and `decodeCborDeterministic` /
`coseUnprotectedToMap` / `decodeCoseSign1` / `CborTag` from
`@forestrie/encoding@0.7.0`.

It turned out to reproduce `forestrie decode-receipt --json` **exactly** —
nested CBOR rendering of header 396 included — which the differential test now
asserts as a full deep-equal on two different receipts. That was not assumed;
the assertion started as a subset match and was strengthened once the runtime
showed it held.

### That file is a placeholder, and should be deleted

`@forestrie/forestrie-cli@0.8.0` (prepared on the `publish-npm` branch, **not
yet on npm**) makes the CLI a public, Node-runnable package with a pure subpath
export `@forestrie/forestrie-cli/decode-receipt`, exposing `decodeReceipt`,
`renderReceipt`, `DecodeReceiptError`, `toJson`, `bytesToHex`, the label tables
and the same `DecodedReceipt` type. It imports only `@forestrie/receipt-verify`
and `@forestrie/encoding`.

Our public surface is deliberately name- and shape-compatible with it. When it
publishes:

1. `pnpm add @forestrie/forestrie-cli@0.8.0` (exact pin, like the others).
2. Delete `src/core/decode-receipt.ts` and re-export from the dependency:
   `export { decodeReceipt, ... } from "@forestrie/forestrie-cli/decode-receipt";`
3. **Re-run `pnpm run check:encoding-single-copy`.** The CLI pins
   `@forestrie/encoding ^0.7.0`, so it _should_ dedupe to our exact `0.7.0` and
   the gate should stay green. Verify it; do not assume it. Two copies of a
   wire-type package is two answers about the same bytes, and the correct
   response to a red gate is to fix the pin, never to add an override.
4. Re-run `pnpm run check:browser-safe`. The subpath is documented as
   runtime-neutral; that gate is what proves it for _our_ module graph.
5. Keep the differential test — it is what would catch the swap changing
   behaviour.

Also confirmed present at 0.7.0 and used by the decoder: `decodeCborDeterministic`,
`CborTag`, `decodeCoseSign1`, `coseUnprotectedToMap`, `encodeGrantPayloadV0Canonical`,
`decodeGrantPayload`, `verifyCoseSign1WithParsedKey`.

## 3. `@modelcontextprotocol/sdk@1.30.0` — zod 4 works directly, no `z.toJSONSchema()` needed

O2's open question was whether `registerTool`'s `outputSchema` path goes
through the SDK's `zod-to-json-schema` dependency (a zod **3** helper) and
would therefore choke on a zod-4 schema. It does not. Probed against a live
in-memory client/server pair:

- `inputSchema` and `outputSchema` both accept a zod-4 **raw shape**
  (`{ key: ZodType }`) and the SDK emits draft-07 JSON Schema itself.
- A `ZodObject` is also accepted, but the raw shape is what the SDK's types
  are written for and it types the handler's argument correctly, so this
  package uses raw shapes and keeps composite types (`z.union`,
  `z.discriminatedUnion`) as property values.
- Nested `z.union` renders as `anyOf`, `z.discriminatedUnion` as `oneOf`,
  `.optional()` drops the key from `required`. All correct.
- `tools/call` returns `structuredContent` alongside `content` with no extra
  plumbing.

`test/node/mcp-smoke.test.ts` keeps this honest: it asserts every tool
advertises an `outputSchema` and that a real call's `structuredContent`
validates against the advertised schema. If a future SDK regresses the zod-4
path, that test goes red rather than the tools silently losing their schemas.

## 4. `forestrie-cli` v0.7.0 release assets exist with the expected names

```
$ gh release view v0.7.0 -R forestrie/forestrie-cli
forestrie-darwin-arm64          a0b68282b39e491382051e2d496e677e35fd5ff814888a5fbf101d27bd0d175b
forestrie-darwin-arm64.sha256
forestrie-linux-x64             f211de74dc7944fb15ab652efddd0a9d6517239adea9c98cb0dd20484eccc1ed
forestrie-linux-x64.sha256
```

Published 2026-08-22. The sidecar contents match GitHub's own asset digests,
so the differential harness's checksum pin has two independent witnesses. The
values are pinned in `test/differential/cli-binary.ts`; the rebase procedure
is in [differential-test.md](differential-test.md).
