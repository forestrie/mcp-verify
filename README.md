# @forestrie/mcp-verify

An MCP server whose only tools are verification primitives for Forestrie
receipts. **No backend, no account, no key, no network.**

```json
{
  "mcpServers": {
    "forestrie-verify": {
      "command": "npx",
      "args": ["-y", "@forestrie/mcp-verify"]
    }
  }
}
```

```
npx -y @forestrie/mcp-verify demo
```

Verification is pure over bytes, so this runs entirely in the caller's
process. An agent that installs it and verifies a receipt has performed the
demonstration **without contacting Forestrie at all**. That is the point, and
everything below is about making it checkable rather than asking you to take
it on faith.

## What it proves

| Tool                   | Reference verb                    | What it answers                                                              |
| ---------------------- | --------------------------------- | ---------------------------------------------------------------------------- |
| `verify_receipt`       | `forestrie verify`                | Were these exact payload bytes sequenced at this entry id?                   |
| `verify_grant_receipt` | `forestrie verify-grant`          | Was this grant admitted to this log — i.e. was the signer entitled to write? |
| `decode_receipt`       | `forestrie decode-receipt --json` | What is actually in this CBOR? (Renders only. Verifies nothing.)             |

Every tool is annotated `readOnlyHint: true, openWorldHint: false`. That is
not decoration: it is the machine-readable form of _"this tool touches
nothing"_, and an agent can see it without running anything.

## What it does not prove — and says so

Verification is four questions, not one. A bare "valid" answers none of them
by name, so every result carries all four:

| Question                                                  | Answered by                 |
| --------------------------------------------------------- | --------------------------- |
| **sealing** — did the operator's signature hold?          | every rung                  |
| **split-view** — is this the same log everyone else sees? | **only the anchored rungs** |
| **authority** — was the signer entitled to write here?    | `verify_grant_receipt` only |
| **attribution** — who was authorised to sign _this_ leaf? | every rung                  |

Each is `ok`, `failed`, or `not_answered_at_this_rung`, with a one-line note.
**`not_answered_at_this_rung` is a real answer** and must reach the user. A
client that renders only `ok` is using this tool wrong.

### The collapse

The golden receipt has a **detached payload**: the COSE payload is `null`, so
the signature covers the MMR _peak_ — a value only knowable after recomputing
it from leaf + inclusion path. At a rung with no independent accumulator, four
structurally different tampers become one indistinguishable answer:

| What was tampered            | `genesis` / `known-log-key`       | `known-accumulator`                                   |
| ---------------------------- | --------------------------------- | ----------------------------------------------------- |
| a byte of the COSE signature | `signature` / `signature_invalid` | **passes** — this rung checks no signature            |
| a byte of the inclusion path | `signature` / `signature_invalid` | `peak_not_in_known_accumulator`, `split-view: failed` |
| the committed grant          | `signature` / `signature_invalid` | `peak_not_in_known_accumulator`, `split-view: failed` |
| the idtimestamp              | `signature` / `signature_invalid` | `peak_not_in_known_accumulator`, `split-view: failed` |
| truncation                   | `parse` / `receipt_malformed`     | `parse` / `receipt_malformed`                         |
| garbage                      | `parse` / `receipt_malformed`     | `parse` / `receipt_malformed`                         |

The tool emits a `detached_payload_stage_collapse` diagnostic exactly when
that applies — **including on success**, because knowing a PASS could not have
distinguished those failures is as much a part of the trust story as the
failure itself.

## The trust ladder

You do not ask for "verification". You say which anchor you are willing to
trust, and the answer tells you which questions that anchor can reach.

| Rung                | Trust root                                | split-view   |
| ------------------- | ----------------------------------------- | ------------ |
| `genesis`           | the log's genesis document                | not answered |
| `known-log-key`     | a log owner key you hold out of band      | not answered |
| `known-accumulator` | an on-chain accumulator snapshot you hold | **answered** |
| `checkpoint-chain`  | a retained `.sth` chain you hold          | **answered** |

A log operator who showed you a private branch would produce a receipt that
verifies _exactly like an honest one_ at the lower two rungs. Both derive
their trust root from material the operator also controls. Nothing about the
arithmetic is wrong; it simply cannot see the question.

The `rpc` rung the reference CLI offers — the only one that touches the
network — is excluded from this package **by construction**. There is no
branch for it, and a CI gate bundles the core for `platform: "browser"` and
fails on any edge to a node builtin, let alone a socket.

Full table, including the two places the runtime disagreed with the design and
won: [docs/trust-ladder.md](docs/trust-ladder.md).

## The demo

Captured from `node ./bin/mcp-verify.mjs demo` — this is real output, not an
illustration.

```
@forestrie/mcp-verify — the trust ladder over the bundled fixtures

No network. No account. No key. No backend. These 118 bytes of
receipt and 160 bytes of genesis ship inside the package.

── Rung 1: genesis ───────────────────────────────────────────────
The log's own genesis document is the trust root.

  the frozen receipt, untouched:
    verify-grant: PASS · rung=genesis · sealing ok, split-view not answered at this rung, authority ok, attribution ok
      parse      ok
      signature  ok
      inclusion  ok
      binding    ok
      ! detached_payload_stage_collapse
      ! rung_answers_no_split_view

  the same receipt, one SIGNATURE byte flipped:
    verify-grant: FAILED at signature (signature_invalid) · rung=genesis · sealing failed, split-view not answered at this rung, authority failed, attribution failed
      parse      ok
      signature  failed   — signature_invalid
      inclusion  skipped
      binding    skipped
      ! detached_payload_stage_collapse
      ! rung_answers_no_split_view

  the same receipt, a wrong IDTIMESTAMP:
    verify-grant: FAILED at signature (signature_invalid) · rung=genesis · sealing failed, split-view not answered at this rung, authority failed, attribution failed
      parse      ok
      signature  failed   — signature_invalid
      inclusion  skipped
      binding    skipped
      ! detached_payload_stage_collapse
      ! rung_answers_no_split_view

Look at those last two. Different tampers. Same answer:
stage=signature reason=signature_invalid. [...]

── Rung 2: known-accumulator ─────────────────────────────────────
Now the trust root is an accumulator snapshot the CALLER holds.

NOTE: this demo derives the snapshot from the clean receipt's own
recomputed peak, because no chain-read snapshot ships with the
fixtures. That makes the PASS below a self-consistency check, not an
independent one. [...]

  the frozen receipt, untouched:
    verify-grant: PASS · rung=known-accumulator · sealing ok, split-view ok, authority ok, attribution ok
      parse      ok
      signature  ok       — not re-checked locally — enforced by univocity at publish; an anchored peak match implies a valid publishing signature
      inclusion  ok
      binding    ok
      anchor     ok       — peak 1/1 at anchored size 2

  the same receipt, a wrong IDTIMESTAMP:
    verify-grant: FAILED at signature (peak_not_in_known_accumulator) · rung=known-accumulator · sealing failed, split-view failed, authority failed, attribution failed
      parse      ok
      signature  failed   — peak_not_in_known_accumulator
      inclusion  skipped
      binding    skipped
      anchor     failed   — peak not found at anchored size 2
      ! accumulator_failure_reported_at_signature_stage

Same bytes. More questions answered. [...]

  one SIGNATURE byte flipped, at the accumulator rung:
    verify-grant: PASS · rung=known-accumulator · sealing ok, split-view ok, authority ok, attribution ok

It PASSES. This rung evaluates no signature at all. [...]
```

The bundled fixtures are also exposed as MCP resources
(`forestrie://fixtures/golden/…`), so an agent can run the demo with no inputs
of its own.

## Not a trust circle

> The root of trust is the univocity checkpoint the receipt chains to, not the
> package; the package supplies the arithmetic, which any independent
> implementation can re-run.

Which is why this repo goes to some trouble to make that re-running possible:

- **A differential test** against the published, sha256-pinned `forestrie`
  release binary. For every tamper variant at every offline rung, our `ok`,
  `stage`, `reason` and `stages[]` must equal the reference's byte for byte.
  Currently 18 tests, zero disagreements. See
  [docs/differential-test.md](docs/differential-test.md).
- **Frozen conformance vectors**, sha256-pinned to their manifest, shipped
  inside the tarball. See [fixtures/PROVENANCE.md](fixtures/PROVENANCE.md).
- **`files` includes `src`.** The package that asks you to trust its
  arithmetic ships the arithmetic.
- **Exact, provenance-attested dependencies** — no bundling, so
  `npm ls` and `npm audit signatures` both see the real graph. Bundling would
  hide `@forestrie/receipt-verify`'s own SLSA attestation behind ours.

The verification itself is `@forestrie/receipt-verify@1.0.0`, which is
published, MIT, and SLSA-attested independently of this package.

## Install weight

`@modelcontextprotocol/sdk@1.30.0` pulls a heavy transitive tree — `express`,
`hono`, `jose`, `cors`, `ajv` — which is an odd shape for a package whose
pitch is "no backend, no network". Two things are true and worth stating
rather than letting you discover:

- **`src/core` never imports the SDK.** Take the `"."` export and you get the
  arithmetic and none of that tree. The browser-safety gate enforces it.
- The network-capable code in there is the SDK's **unused HTTP transports**.
  This package constructs only `StdioServerTransport`.

Worth revisiting when the SDK offers a slimmer stdio-only entry.

## Development

```
mise install           # node 22.14.0, pnpm 10.6.5
pnpm install
pnpm test              # browser-safe gate + encoding-copy gate + unit tests
pnpm test:differential # needs the pinned forestrie CLI binary
pnpm build
```

Conventions and invariants: [AGENTS.md](AGENTS.md).

## Release checklist

1. Bump `version` in `package.json` **and** `PACKAGE_VERSION` in
   `src/core/version.ts` in the same PR. The MCP smoke test asserts they
   agree, so a forgotten bump is a red test rather than a lie in `initialize`.
2. Merge to `main`.
3. `git tag v<version> && git push --tags`.
4. `publish.yml` asserts the tag matches `package.json`, runs the full gate,
   builds, packs, and publishes via OIDC trusted publishing with provenance.
5. Confirm `npm view @forestrie/mcp-verify dist.attestations` is populated.

The **first** publish must be by hand: npm's trusted-publisher registration
cannot be created for a package that does not exist yet.

**Phase 2/3, not now:** `mcpName: "dev.forestrie/verify"` in `package.json`
and a `server.json` are deliberately absent. They must land in the _same PR_
as the apex DNS TXT record on `forestrie.dev` — adding either earlier
publishes an identity claim that nothing backs. `verify --self` is reserved by
the CLI today and refuses with a version number rather than an
unknown-command error.

## Licence

MIT.
