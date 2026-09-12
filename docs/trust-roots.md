# The trust ladder

Inlined here until a public protocol spec exists. Everything below is
reproducible from the bundled fixtures with `npx @forestrie/mcp-verify demo`
and is asserted by `test/core/rung-table.test.ts`.

## The four questions

Verification is not one question. It is four, and a bare "valid" answers none
of them by name.

| Question        | What it asks                                  | What answers it                                                                                                                |
| --------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **sealing**     | Did the log operator's signature hold?        | A COSE check under the rung's trust root — or, at the anchored rungs, the contract's refusal to publish an unsigned checkpoint |
| **split-view**  | Is this the same log everyone else sees?      | An accumulator you trust _independently of the log operator_. Nothing else.                                                    |
| **authority**   | Was the signer entitled to write to this log? | `verify_grant_receipt`, whose leaf **is** a grant                                                                              |
| **attribution** | Who was authorised to sign _this_ leaf?       | The leaf commitment: `SHA-256(idtimestamp ‖ SHA-256(payload))`                                                                 |

Every result carries all four, each as `ok`, `failed`, or
`not_answered_at_this_rung` with a one-line note.
`not_answered_at_this_rung` **is a real answer.** A client that renders only
`ok` is using this tool wrong.

## The rungs

| Rung                | Trust root                                | sealing                   | split-view       | authority           | attribution |
| ------------------- | ----------------------------------------- | ------------------------- | ---------------- | ------------------- | ----------- |
| `genesis`           | the log's genesis document                | answered                  | **not answered** | grant receipts only | answered    |
| `known-log-key`     | a log owner key you hold out of band      | answered                  | **not answered** | grant receipts only | answered    |
| `known-accumulator` | an on-chain accumulator snapshot you hold | answered _by implication_ | **answered**     | grant receipts only | answered    |
| `checkpoint-chain`  | a retained `.sth` chain you hold          | answered _by implication_ | **answered**     | grant receipts only | answered    |

The `rpc` rung the reference CLI offers — the only one that touches the
network — is excluded from this package **by construction**. There is no
branch for it and no code path that could reach one, and
`pnpm run check:browser-safe` proves the core has no edge to a node builtin,
let alone a socket.

## The collapse

This is the thing the plan was written to make legible.

The golden receipt has a **detached payload**: its COSE payload is `null`, so
the signature covers the MMR **peak** — a value only knowable after recomputing
it from leaf + inclusion path. At a rung with no independent accumulator to
check that peak against, four structurally different tampers produce one
indistinguishable answer:

| What was tampered            | genesis / known-log-key           | known-accumulator                                     |
| ---------------------------- | --------------------------------- | ----------------------------------------------------- |
| a byte of the COSE signature | `signature` / `signature_invalid` | **PASSES** — see below                                |
| a byte of the inclusion path | `signature` / `signature_invalid` | `peak_not_in_known_accumulator`, `split-view: failed` |
| the committed grant          | `signature` / `signature_invalid` | `peak_not_in_known_accumulator`, `split-view: failed` |
| the idtimestamp              | `signature` / `signature_invalid` | `peak_not_in_known_accumulator`, `split-view: failed` |
| truncation                   | `parse` / `receipt_malformed`     | `parse` / `receipt_malformed`                         |
| garbage                      | `parse` / `receipt_malformed`     | `parse` / `receipt_malformed`                         |

The tool emits a `detached_payload_stage_collapse` diagnostic exactly when the
rung is `genesis` or `known-log-key` **and** the receipt is detached-payload —
including on success. Knowing that a PASS _could not have distinguished_ those
failures is as much a part of the trust story as the failure itself.

An _attached_-payload receipt does report a distinct `inclusion` failure at
these rungs; the collapse is a property of detached payloads, not of the
verifier.

## Three places the runtime disagreed with the design, and what won

The design was written before the arithmetic was run. Where they disagreed the
runtime won, because a plan is a hypothesis about arithmetic and the
arithmetic is the authority. All three are asserted deliberately in
`test/core/rung-table.test.ts` so nobody "fixes" them back.

### 1. A flipped signature byte PASSES at the accumulator rung

The design table said a signature tamper would fail at both rungs. It does
not, and the reason matters more than the row.

`verifyReceiptOfflineAgainstKnownAccumulator` **evaluates no signature at
all.** It parses, recomputes the peak from leaf + inclusion path, and matches
that peak against the accumulator you trust. A signature flip touches neither
the leaf nor the path, so the peak still matches — and a peak that matches a
consistency-gated on-chain accumulator _is_ the proof, because univocity
refuses to publish a checkpoint whose signature does not verify under the
log's live delegation.

So `sealing` is answered `ok` here with the note _"implied by the anchor"_,
and the `signature` stage row carries _"not re-checked locally — enforced by
univocity at publish"_. Both are true, and both are visible. What would be
dishonest is a bare `signature: ok` with no explanation.

**If you make this rung re-check the signature, you destroy the separation
this whole document is about.** The point of climbing the ladder is that the
upper rung stops depending on the signature, which is exactly why it can tell
a bad path from a bad signature when the lower rung cannot.

### 2. The accumulator rung labels its failures `stage=signature`

`verifyReceiptOfflineAgainstKnownAccumulator` returns

```
{ ok: false, stage: "signature", reason: "peak_not_in_known_accumulator" }
```

— `stage: "signature"`, although no signature was evaluated. Same for
`receipt_newer_than_known_accumulator`. That is upstream's label
(`@forestrie/receipt-verify@1.0.0`, `known-accumulator.ts`), and this package
passes `stage`/`reason` through **verbatim** so `stages[]` stays comparable
with the reference CLI's contract.

The D3 separation is real; it just lives in `reason` and in
`questions["split-view"]` rather than in the stage name. The
`accumulator_failure_reported_at_signature_stage` diagnostic says so in the
tool output rather than leaving a reader to infer it. Filed upstream as a
finding.

### 3. This package's accumulator rung means something different from the CLI's

`forestrie verify --known-accumulator` runs the genesis/known-key offline
verify **first** and only checks the anchor if that passed — so its stage
collapse survives into the anchored rung, and a path tamper still reports
`signature_invalid` there.

Here, `known-accumulator` is a standalone rung: the accumulator is the sole
authority. That is what produces the separation, it is what D2's rung union
describes (the `known-accumulator` variant takes no genesis and no key), and
it is why those two rungs are outside the differential matrix. See
[differential-test.md](differential-test.md).

## What "no split-view protection" actually means

A log operator who showed you a private branch — a fork containing your entry
but visible to nobody else — would produce a receipt that verifies **exactly
like an honest one** at the `genesis` and `known-log-key` rungs. Both rungs
derive their trust root from material the operator also controls. Nothing
about the arithmetic is wrong; it simply cannot see the question.

Climbing to `known-accumulator` or `checkpoint-chain` is what makes that
question answerable, and the anchor has to come from somewhere the operator
does not control: a chain read of your own, or someone else's you have reason
to trust. **Never source a snapshot unauthenticated from the same store as the
tiles** — that silently re-internalises the operator trust the anchor exists to
remove.

## The stages, and why they are also reported

`stages[]` is the mechanical pipeline — `parse`, `signature`, `inclusion`,
`binding`, each `ok | failed | skipped` — and it is exactly the reference
CLI's `VerifyReport` contract, which its own CI asserts. It is reported
unmodified so `test/differential/` can compare the two implementations field
for field. The four questions are what that verdict is _evidence for_; the
stages are what actually ran. Both, always.
