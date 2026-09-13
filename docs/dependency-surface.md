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
   known-accumulator root has exactly one entry point for both receipt kinds,
   and the caller supplies the leaf `inner` hash: `SHA-256(payload)` for a
   payload receipt, `grantCommitmentHashFromGrant(grant)` for a grant receipt.
   That is why `src/core/verify-receipt.ts` and
   `src/core/verify-grant-receipt.ts` differ only in how they produce `inner`
   and which offline verifier they call.
2. `verifyReceiptOfflineAgainstKnownAccumulator` **does not check any
   signature.** It parses, recomputes the peak from leaf + proof, and matches
   it against the caller's trusted accumulator. That is the correct shape for
   the root — the accumulator _is_ the authority — and it is what makes the
   separation real rather than cosmetic. See
   [trust-roots.md](trust-roots.md).

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

Consequence for the stage-collapse table: the separation under the accumulator roots
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

### Delegating to `@forestrie/forestrie-cli` — tried twice, reverted twice (plan-2609-02 step P5.5)

`@forestrie/forestrie-cli` published to npm from `0.8.0`, making the CLI a
public, Node-runnable package with a pure subpath export
`@forestrie/forestrie-cli/decode-receipt`, exposing `decodeReceipt`,
`renderReceipt`, `DecodeReceiptError`, `toJson`, `bytesToHex`, the label
tables and the same `DecodedReceipt` type. It imports only
`@forestrie/receipt-verify` and `@forestrie/encoding`. Both purity gates
tolerate it: with the dependency installed, `@forestrie/encoding` still
dedupes to exactly one copy at `0.7.0`, and `src/core` still bundles clean
for `platform: "browser"`. Neither attempt failed on a gate in `AGENTS.md`'s
sense. Both failed on rendered output.

**Attempt 1, against `0.8.0`.** The CLI's published label registry did not
carry two forestrie private-use codepoints real receipts use: COSE algorithm
`-65800` (`ALG_ES256_WEBAUTHN`) and header label `-65801` (the session-key
endorsement, `TBD2`). Delegating silently turned their `name` into `null`.
No fixture in this repo's suite (golden, burial or self-bundle) exercises
either codepoint, so the existing tests and the differential comparison all
stayed green and the regression was caught by review, not by a gate. Two
fixture-free tests were added at the foot of
`test/core/decode-receipt.test.ts` asserting the strings directly against the
tables, so that next time it would be the gate.

**Attempt 2, against `0.8.1`.** forestrie-cli#54 added `-65800` and `-65801`
— plus header label `-65800` (WebAuthn assertion envelope) and `-66535`
(on-chain delegation proof) — from the public registry. The two tests caught
it anyway, exactly as intended, because the CLI names those codepoints with
**different text**:

|                              | here                                     | `@forestrie/forestrie-cli@0.8.1`                                                                                          |
| ---------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `ALG_NAMES[-65800]`          | `ES256-WebAuthn (forestrie private-use)` | `ES256-WebAuthn (forestrie private-use; delegation proofs and certificates only, never checkpoint-signing)`               |
| `HEADER_LABELS[-65801].note` | `forestrie private-use`                  | `forestrie TBD2: the endorsement COSE_Sign1, embedded as a bstr (unprotected, leaf-admission-and-session-endorsement.md)` |

(`HEADER_LABELS[-65801].name` agrees: `session key endorsement`.)

Both strings are rendered output, not commentary — `note` reaches
`DecodedHeaderEntry.note` and the `ALG_NAMES` value reaches the `alg.name`
field. Neither wording is wrong, and the CLI's is arguably more useful. But
adopting it changes what `decode_receipt` prints, and that is a product
decision taken deliberately, not a side effect of adding a dependency. The
tests were **not** loosened to let the swap through; loosening them would
have shipped the output change silently, which is the one thing they exist
to prevent.

`src/core/decode-receipt.ts` therefore stays a local renderer, tracking the
authoritative registry —
[forestrie/protocol `spec/label-registry.md`](https://github.com/forestrie/protocol/blob/main/spec/label-registry.md)
— rather than the dependency.

There is a consolation, and it is not small: because the two implementations
are independent, the differential test's `decode_receipt` row is real
evidence. Delegate, and both sides of that comparison run the same code and
the row asserts nothing. See [differential-test.md](differential-test.md).

**Revisit when the two tables agree textually.** The fix belongs upstream of
both: settle the wording in the registry, land it in `forestrie-cli`, then
adopt it here in a change whose subject says it is changing rendered output.
Then:

1. `pnpm add -E @forestrie/forestrie-cli@<version>` (exact pin, like the
   others).
2. Delete `src/core/decode-receipt.ts`'s implementation and re-export from
   the dependency:
   `export { decodeReceipt, ... } from "@forestrie/forestrie-cli/decode-receipt";`
3. **Re-run `pnpm run check:encoding-single-copy`.** The CLI pins
   `@forestrie/encoding ^0.7.0`, so it _should_ dedupe to our exact `0.7.0` and
   the gate should stay green. Verify it; do not assume it. Two copies of a
   wire-type package is two answers about the same bytes, and the correct
   response to a red gate is to fix the pin, never to add an override.
4. Re-run `pnpm run check:browser-safe`. The subpath is documented as
   runtime-neutral; that gate is what proves it for _our_ module graph.
5. Re-run the two label-name unit tests in `test/core/decode-receipt.test.ts`
   against the dependency's exports. If they pass unchanged, the tables agree
   and the swap is safe. If they fail, the swap is an output change again —
   stop, and say so, rather than editing the expectation.
6. Keep the differential test, and accept that it weakens to a self-comparison
   for the decode row.

Also confirmed present at 0.7.0 and used by the decoder: `decodeCborDeterministic`,
`CborTag`, `decodeCoseSign1`, `coseUnprotectedToMap`, `encodeGrantPayloadV0Canonical`,
`decodeGrantPayload`, `verifyCoseSign1WithParsedKey`.

## 3. `@modelcontextprotocol/sdk@1.30.0` — zod 4 works directly, no `z.toJSONSchema()` needed

The open question was whether `registerTool`'s `outputSchema` path goes
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

### Install weight

The SDK pulls a heavy transitive tree — `express`,
`hono`, `jose`, `cors`, `ajv` — which is an odd shape for a package whose
pitch is "no backend, no network". Two things are true and worth stating
rather than letting you discover:

- **`src/core` never imports the SDK.** Take the `"."` export and you get the
  arithmetic and none of that tree. The browser-safety gate enforces it.
- The network-capable code in there is the SDK's **unused HTTP transports**.
  This package constructs only `StdioServerTransport`.

Worth revisiting when the SDK offers a slimmer stdio-only entry.

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
