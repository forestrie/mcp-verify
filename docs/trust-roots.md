# Trust roots

Every root runs the same arithmetic. What differs is what the recomputed peak
is related to, and therefore which questions the answer can reach. You do not
ask for "verification". You say which root you trust, and the result says what
that root can see.

The four roots are not ordered by strength. Two are **signature roots**: they
rest on a key and check the receipt's signature locally. Two are
**accumulator roots**: they rest on an accumulator the operator does not
control, match the peak against it, and evaluate no signature at all. A
receipt that verifies under one and not the other is not a contradiction;
they ask different questions. Which root is right depends on what you hold
and what you need to know. The reference CLI selects the root by flag.

Everything below is reproducible from the bundled fixtures with
`npx @forestrie/mcp-verify demo` and asserted by
`test/core/root-table.test.ts`. Background on what transparency is and what a
receipt contains: [TRANSPARENCY.md](../TRANSPARENCY.md).

| Root                | What you supply                                                              | What the verdict rests on                                                                                |
| ------------------- | ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `genesis`           | the forest's genesis document, captured when you registered                  | the bootstrap key in genesis, with the receipt's delegation certificate resolved under it                |
| `known-log-key`     | a log owner key you hold out of band                                         | your channel for that key: "this key owns this log" is asserted by where you got it, not proven          |
| `known-accumulator` | a snapshot of the log's peaks at a size, from a chain read                   | the univocity contract, which refuses to publish a checkpoint whose signature or consistency proof fails |
| `checkpoint-chain`  | a retained chain of `.sth` checkpoints, plus `genesis` or a key for its base | your own retention: each link's signature is checked over the accumulator folded from the previous link  |

### When each root is the effective choice

- **`genesis`** when the genesis document is all you have. It is
  self-contained. It roots receipts from the root log or a direct delegate;
  the offline walk that would root a deeper child log is not implemented,
  here or in the reference CLI. Its trust value depends on when you obtained
  it: see [The genesis document](#the-genesis-document).
- **`known-log-key`** when the log owner's key reached you through a channel
  you already trust: a contract, an onboarding document, a pinned known-hosts
  entry. This is the standard SCITT relying-party posture. It is exactly as
  strong as that channel, with no view of rotation or revocation. Never fetch
  the key from the operator's own API or store.
- **`known-accumulator`** when you can obtain one authenticated chain read and
  reuse it. The snapshot never needs to be current, only trusted: every
  published accumulator is a committed prefix of every later one, so a match
  at size _N_ holds forever. Staleness limits coverage, not validity; a
  receipt newer than the snapshot fails closed with a refresh remedy, not as
  tamper. Never source the snapshot from the operator's own store, and check
  its log id and contract binding yourself, because this package does not.
- **`checkpoint-chain`** when you hold the checkpoints and have neither chain
  nor tile access, or when log growth has buried the receipt's peak. Each
  later link's signed consistency proof commits the earlier accumulator
  forward, so a match at any link is proof. This is the only fully offline
  route for a buried receipt. A log whose early checkpoints predate
  contiguous chaining reports `legacy_chain_break`; that is a property of the
  log, not tamper.

### The genesis document

The genesis document is a Forestrie operator record. Forestrie writes one
when a forest is created, and it binds three things: the forest's id, the
**bootstrap public key** that every log in that forest ultimately chains to,
and the **chain binding**, the chain id and univocity contract address the
forest publishes checkpoints to. The `genesis` root reads the bootstrap key
from it and resolves the receipt's delegation certificate under that key.
Nothing else in the document is consulted.

Because the operator writes it and the operator serves it, _when_ you
obtained your copy decides what verifying under it proves.

- **Captured at registration and kept.** You hold the key Forestrie
  committed to before it knew what you would later check. A receipt that
  verifies under it was sealed by that key or a delegate of it, and a later
  substitution of key or forest would fail against your copy. This is the
  known-hosts posture: trust on first use, then pinned. It is the `genesis`
  root as intended. Capture it when you first register with the forest, or
  at creation: `forestrie onboard-genesis --out` fetches it back then.
- **Fetched from Forestrie at the time of the check.** The operator now
  supplies both the receipt and the root it is checked under. A pass proves
  the receipt is consistent with a document the operator chose to serve you
  today, and nothing more. An operator minting a fresh key and genesis for
  your session would pass identically. This is `known-log-key` with the key
  fetched from the operator, which is exactly what the reference CLI says
  never to do.

If you did not keep a copy, obtain one from somewhere other than the
operator's store, or cross-check its bootstrap key against a source you
trust independently. Or use an accumulator root, which does not depend on
the genesis document at all.

A call takes one root. `checkpoint-chain` also accepts both `genesis` and
`keyXy`, and tries both for each link. To have both a local signature check
and a split-view answer, run the same bytes against two roots; the arithmetic
does not change between them.

The `rpc` mode the reference CLI offers — the only one that touches the
network — is excluded from this package **by construction**. There is no
branch for it, and a CI gate bundles the core for `platform: "browser"` and
fails on any edge to a node builtin, let alone a socket.

## The four questions

A bare "valid" names no question. Every result carries these four, each
`ok`, `failed`, or `not_answered_by_this_root`, with a one-line note:

| Question                                                               | Name                 | Answered under                                                                   | Trust anchor                                                                   |
| ---------------------------------------------------------------------- | -------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Did the log operator sign for this leaf's addition?                    | **sealing**          | every root: checked locally under a signature root, implied under an accumulator | the operator's key, or an accumulator that could only hold a signed checkpoint |
| Did the log operator show the same log to everyone (one true history)? | **split-view**       | `known-accumulator` and `checkpoint-chain` only                                  | an accumulator the operator does not control                                   |
| Did the leaf signer have authority to write to the log?                | **append-authority** | `verify_grant_receipt` only, under any root                                      | the committed grant that admitted the signer, itself sealed into the log       |
| Who signed this leaf?                                                  | **attribution**      | every root                                                                       | your own copy of the payload bytes and the entry id the leaf commits           |

**`not_answered_by_this_root` is a real answer** and must reach the user. A
client that renders only `ok` is using this tool wrong.

## The stage collapse: what a signature root cannot distinguish

Results also report the **stage** that failed: `parse`, `signature`,
`inclusion`, or `binding`. With a detached payload the signature covers the
peak, so it can only be checked over the peak recomputed from the leaf and
path _you_ supplied. Under a signature root that folds two different
situations into one answer and hides a third entirely. Each cell is the
`reason` the result reports; every row is a real run over the frozen receipt,
reproduced in the tests as the second column describes.

| What is actually wrong                                                                                        | How the tests reproduce it                                                      | `genesis`, `known-log-key`                                | `known-accumulator`                                  |
| ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | --------------------------------------------------------- | ---------------------------------------------------- |
| the operator's signature is forged or corrupt                                                                 | flip a byte of the COSE signature                                               | `signature_invalid`                                       | **passes**: no signature is evaluated                |
| the signature is genuine, but the leaf you hold is not the one it seals                                       | alter the inclusion path, the committed grant, or the idtimestamp               | `signature_invalid`, indistinguishable from the row above | `peak_not_in_known_accumulator`, split-view `failed` |
| the signature is genuine and seals your leaf, but into a state the operator never published: a private branch | verify the untouched receipt against an accumulator that does not hold its peak | **passes**, indistinguishable from an honest receipt      | `peak_not_in_known_accumulator`, split-view `failed` |
| the receipt is structurally broken                                                                            | truncate it, or feed garbage                                                    | `receipt_malformed`                                       | `receipt_malformed`                                  |

An accumulator root does not separate the middle rows either, and does not
need to: both mean the leaf is not in the agreed history. `checkpoint-chain`
behaves the same and reports `peak_not_in_checkpoint_chain`. The
`detached_payload_stage_collapse` diagnostic is emitted whenever a signature
root verifies a detached-payload receipt, **including on success**: a PASS
that could not have told those rows apart is part of the trust story.

An _attached_-payload receipt does report a distinct `inclusion` failure at
the signature roots; the collapse is a property of detached payloads, not of
the verifier.

## Three places the runtime disagreed with the design, and what won

The design was written before the arithmetic was run. Where they disagreed the
runtime won, because a plan is a hypothesis about arithmetic and the
arithmetic is the authority. All three are asserted deliberately in
`test/core/root-table.test.ts` so nobody "fixes" them back.

### 1. A flipped signature byte PASSES under an accumulator root

The design table said a signature tamper would fail under every root. It does
not, and the reason matters more than the row.

`verifyReceiptOfflineAgainstKnownAccumulator` **evaluates no signature at
all.** It recomputes the peak from leaf + inclusion path and matches it
against the accumulator you trust. A signature flip touches neither, so the
peak still matches, and a match against a consistency-gated on-chain
accumulator _is_ the proof: univocity refuses to publish a checkpoint whose
signature does not verify. So `sealing` is `ok` with the note _"implied by
the anchor"_, and the `signature` stage row says _"not re-checked locally"_.
Both are visible; a bare `signature: ok` would be the dishonest option.

**If you make this root re-check the signature, you destroy the separation
this whole document is about.** The point of an accumulator root is that it
stops depending on the signature, which is exactly why it can tell a bad path
from a bad signature when a signature root cannot.

### 2. The accumulator roots label their failures `stage=signature`

`verifyReceiptOfflineAgainstKnownAccumulator` returns

```
{ ok: false, stage: "signature", reason: "peak_not_in_known_accumulator" }
```

— `stage: "signature"`, although no signature was evaluated. Same for
`receipt_newer_than_known_accumulator`. That is upstream's label
(`@forestrie/receipt-verify@1.0.0`, `known-accumulator.ts`), and this package
passes `stage`/`reason` through **verbatim** so `stages[]` stays comparable
with the reference CLI's contract.

The separation is real; it just lives in `reason` and in
`questions["split-view"]` rather than in the stage name. The
`accumulator_failure_reported_at_signature_stage` diagnostic says so in the
tool output rather than leaving a reader to infer it. Filed upstream as a
finding.

### 3. This package's `known-accumulator` means something different from the CLI's, for now

`forestrie verify --known-accumulator` runs the genesis or known-key verify
**first** and checks the anchor only if that passed, so its stage collapse
survives into the accumulator check. Here the accumulator is the sole
authority and no signature is evaluated. That is what produces the
separation, and it is why the two accumulator roots are outside the
differential matrix: see [differential-test.md](differential-test.md).

A planned CLI change lets `--known-accumulator` stand alone the same way,
closing this gap; until it ships, the two implementations disagree here by
design, not by accident.

## The stages, and why they are also reported

`stages[]` is the mechanical pipeline — `parse`, `signature`, `inclusion`,
`binding`, each `ok | failed | skipped` — and it is exactly the reference
CLI's `VerifyReport` contract, which its own CI asserts. It is reported
unmodified so `test/differential/` can compare the two implementations field
for field. The four questions are what that verdict is _evidence for_; the
stages are what actually ran. Both, always.

## The demo

Captured from `node ./bin/mcp-verify.mjs demo` — this is real output, not an
illustration.

```
@forestrie/mcp-verify — two trust roots over the bundled fixtures

No network. No account. No key. No backend. These 118 bytes of
receipt and 160 bytes of genesis ship inside the package.

── Trust root: genesis ───────────────────────────────────────────
The log's own genesis document is the trust root.

  the frozen receipt, untouched:
    verify-grant: PASS · root=genesis · sealing ok, split-view not answered at this root, append-authority ok, attribution ok
      parse      ok
      signature  ok
      inclusion  ok
      binding    ok
      ! detached_payload_stage_collapse
      ! root_answers_no_split_view

  the same receipt, one SIGNATURE byte flipped:
    verify-grant: FAILED at signature (signature_invalid) · root=genesis · sealing failed, split-view not answered at this root, append-authority failed, attribution failed
      parse      ok
      signature  failed   — signature_invalid
      inclusion  skipped
      binding    skipped
      ! detached_payload_stage_collapse
      ! root_answers_no_split_view

  the same receipt, a wrong IDTIMESTAMP:
    verify-grant: FAILED at signature (signature_invalid) · root=genesis · sealing failed, split-view not answered at this root, append-authority failed, attribution failed
      parse      ok
      signature  failed   — signature_invalid
      inclusion  skipped
      binding    skipped
      ! detached_payload_stage_collapse
      ! root_answers_no_split_view

Look at those last two. Different tampers. Same answer:
stage=signature reason=signature_invalid. [...]

── Trust root: known-accumulator ─────────────────────────────────
Now the trust root is an accumulator snapshot the CALLER holds.

NOTE: this demo derives the snapshot from the clean receipt's own
recomputed peak, because no chain-read snapshot ships with the
fixtures. That makes the PASS below a self-consistency check, not an
independent one. [...]

  the frozen receipt, untouched:
    verify-grant: PASS · root=known-accumulator · sealing ok, split-view ok, append-authority ok, attribution ok
      parse      ok
      signature  ok       — not re-checked locally — enforced by univocity at publish; an anchored peak match implies a valid publishing signature
      inclusion  ok
      binding    ok
      anchor     ok       — peak 1/1 at anchored size 2

  the same receipt, a wrong IDTIMESTAMP:
    verify-grant: FAILED at signature (peak_not_in_known_accumulator) · root=known-accumulator · sealing failed, split-view failed, append-authority failed, attribution failed
      parse      ok
      signature  failed   — peak_not_in_known_accumulator
      inclusion  skipped
      binding    skipped
      anchor     failed   — peak not found at anchored size 2
      ! accumulator_failure_reported_at_signature_stage

Same bytes. More questions answered. [...]

  one SIGNATURE byte flipped, under the accumulator root:
    verify-grant: PASS · root=known-accumulator · sealing ok, split-view ok, append-authority ok, attribution ok

It PASSES. This root evaluates no signature at all. [...]
```

The bundled fixtures are also exposed as MCP resources
(`forestrie://fixtures/golden/…`), so an agent can run the demo with no inputs
of its own.

`verify_self` / `verify --self` run this same arithmetic against this
package's own release receipt, defaulting to `known-log-key` rather than
`genesis` for a reason specific to that receipt's log topology:
[docs/self-registration.md](self-registration.md).
