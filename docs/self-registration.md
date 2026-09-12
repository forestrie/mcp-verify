# Self-registration

Every release registers a small binding document in a Forestrie transparency
log, and ships the receipt inside the tarball it describes. This is
plan-2609-02 step 2.3; the tool that verifies the bundle offline
(`verify_self` / `verify --self`) is steps 2.4/2.5, implemented below. The
`forestrie://self/…` MCP resource namespace in `src/node/server.ts` registers
the six bundle files when `fixtures/self/` is present, and nothing when it is
not.

## What gets registered

`scripts/self-register.mjs` runs between `pnpm build` and `pnpm pack` in the
release workflow (`.github/workflows/publish.yml`):

1. Writes `provenance.json`:

   ```json
   {
     "name": "@forestrie/mcp-verify",
     "version": "0.2.0",
     "gitCommit": "…",
     "builtAt": "…"
   }
   ```

   `serverJsonSha256` is **not** in this list yet. D4's field set includes it,
   but AGENTS.md forbids adding `server.json` before the apex DNS TXT record
   lands (phase 3) — a field naming a file that does not exist would be a
   claim nothing backs. It is added in the same PR that adds `server.json`.

2. Signs `provenance.json` with `forestrie sign-statement` (plain COSE Sign1,
   ES256) using the release key.
3. Registers the signed statement with `forestrie register --timeout 300
--json` and waits for the receipt — a poll loop against a SCRAPI
   `303`/status/receipt redirect chain, not a single request.
4. Fetches the forest's kept-copy genesis (see below).
5. Derives the release key's public point (`x‖y`, 64 raw bytes, standard
   base64) from `FORESTRIE_RELEASE_KEY_PEM` via `node:crypto` — see "The
   grant chain: recorded, not walked" below for why this is bundled at all.
6. Bundles all of it under `fixtures/self/`: `provenance.json`,
   `statement.cose`, `receipt.cbor`, `genesis.cbor`, `log-key.xy.b64`,
   `entry-id.txt`, and a `manifest.json` carrying the sha256 of each.

`fixtures/self/` is **generated, and gitignored** — it never lands in a
commit. `package.json#files` lists it explicitly (alongside the existing
`fixtures` entry) so `pnpm pack` still ships it inside the tarball on the one
run where it exists: the release workflow, after this script has run.
`src/node/fixtures.ts`'s `listSelfFixtures()` tolerates its absence in every
other checkout — it returns `[]` rather than throwing, so a repo clone with
no release history behaves the same as one mid-release.

## The genesis question, resolved

`verify --genesis genesis.cbor` expects the **forest's own genesis document**
— one document per forest, shared by every log in it, including a child data
log like this package's publications log. It is not "the log's own"
document; no such thing exists for a data log created via `create-log`.

Evidence:

- `@forestrie/receipt-verify@1.0.0`'s `decodeTrustRootFromGenesis` (this
  package's own pinned dependency) extracts one `bootstrapKey` field from a
  v2 forest-genesis document as the ES256 trust root — a per-forest artifact,
  not a per-log one.
- canopy's demo (`docs/demo/forestrie-demo.md:241–246`) fetches genesis
  **once**, keyed by the forest's bootstrap log id:
  `GET $FORESTRIE_BASE_URL/api/forest/$BOOTSTRAP_LOG_ID/genesis`.
- The same cached `genesis.cbor` is reused later
  (`docs/demo/forestrie-demo.md:849–851`) to verify a receipt for a **child
  data log** (`--log-id "$DATA_LOG_ID"`), proving one forest genesis serves
  every log in it.
- canopy's registration handler
  (`packages/apps/canopy-api/src/scrapi/register-signed-statement.ts`) calls
  `getParsedGenesis(bootstrapLogIdSegment, …)` using the **same id** as the
  URL's first path segment in `POST /register/{bootstrapLogId}/entries` —
  and documents explicitly that `grant.logId` (from inside the
  `Forestrie-Grant`, not the URL) is always the actual target log. The URL
  segment is the forest's bootstrap id.
- forestrie-cli's `register-flow.ts` passes the CLI's single `--log-id` flag
  straight through as that URL segment (`bootstrapLogId: params.logId`).

So `FORESTRIE_LOG_ID` — the same value `forestrie register --log-id` already
needs — is exactly the id this script uses for
`GET {FORESTRIE_BASE_URL}/api/forest/{FORESTRIE_LOG_ID}/genesis`. No second
env var is needed, and provisioning has confirmed `FORESTRIE_LOG_ID` is
indeed the forest's bootstrap id — see the table below and the next section
for what that turned out to mean in practice.

## The grant chain: recorded, not walked

Provisioning surfaced a runtime finding that changes what `verify_self`
(step 2.4) must default to. The publications log is not a direct child of
the forest root — it is a **grandchild**: root → auth log → publications
log. That chain is real and it is recorded in the logs (the `create-log`
grants that built it), but as of today **neither `forestrie-cli` nor
`@forestrie/receipt-verify` walks a grant chain down to a child log** — the
`genesis` root's offline walk only reaches a log's direct delegate. The
practical consequence: a receipt for this log's own entries verifies offline
under `known-log-key` (the log owner's key, held out of band) today, and
**fails under `genesis` with `delegation_invalid`**, because `genesis`
cannot see past the one hop it does resolve.

This is why `log-key.xy.b64` — the release key's public point — is bundled
at all: `known-log-key` needs a caller-known key from a channel it already
trusts, and this bundle IS that channel for the package's own receipt.
`verify_self` defaults to `known-log-key` with this bundled point, **not**
`genesis`, for exactly this reason. `genesis.cbor` still ships alongside it —
it costs one fetch, it is still the forest's root document and useful for
anyone auditing the chain by hand, and the walk down to a child log may land
in `forestrie-cli` or `@forestrie/receipt-verify` later, at which point
`genesis` becomes the default again with no bundle change needed here. Until
then, treat the genesis document as recorded evidence of the chain, not as
something this package's own verification currently walks.

## `verify_self` and `verify --self`

Steps 2.4/2.5: an offline check, over the bundle above, that this build's own
receipt actually vouches for the bytes it ships. The `verify_self` MCP tool
takes no required input — it loads `fixtures/self/` itself via
`src/node/fixtures.ts`'s `loadSelfBundle()` — and `verify --self` narrates
the same run on the CLI. Both defer to `verifySelf` (`src/core/verify-self.ts`),
the pure function everything above this line has been building toward.

**Default root: `known-log-key`, with the bundle's own `log-key.xy.b64`.**
Pass `{root: "genesis"}` to see `delegation_invalid` reported instead (the
previous section explains why), or a caller-supplied `known-accumulator`
snapshot to additionally answer split-view — the bundle ships no snapshot of
its own, so that root is never a default.

**What it checks, beyond a plain `verify_receipt` call:**

1. **The receipt's leaf commits `statement.cose`, never `provenance.json`
   directly.** Verified at capture with the reference CLI (see
   `test/fixtures/self-bundle/PROVENANCE.md`): `--payload statement.cose`
   PASSES; `--payload provenance.json` reports `signature_invalid`. So the
   receipt check always runs against `statementCose`.
2. **`statement.cose`'s signed payload equals `provenance.json`,
   byte-for-byte.** Decoded independently of the receipt
   (`@forestrie/encoding`'s `decodeCoseSign1`), and checked regardless of
   which root the caller chose for (1) — this is the attribution channel,
   not the receipt's inclusion root.
3. **`statement.cose`'s ES256 signature verifies under `log-key.xy.b64`.**
   Same independence: always the bundle's own key, because attribution here
   means "the log owner signed this", not "some root I happened to pick
   accepts it".
4. **`provenance.json` is parsed** and surfaced as `self.provenance`:
   `{name, version, gitCommit, builtAt}`, or `null` if a tampered document
   does not even parse as JSON.

**The attribution mapping.** A plain `verify_receipt` call's `attribution`
question only says the receipt commits the exact statement bytes at the
exact entry id — it says nothing about who signed those bytes. `verifySelf`
folds checks 2 and 3 above into `attribution` too, so a passing answer means
"the log owner's key signed exactly this `provenance.json`, and the receipt
commits that signed statement" — nothing weaker. A mismatch on either check
fails `attribution` even when the mechanical receipt check on its own would
have passed.

**The chain-not-walked diagnostic.** Every run at `known-log-key` or
`genesis` carries `self_chain_not_walked`: "the genesis → root grant → auth
log → publications log chain is recorded in the logs but not walked by this
verifier; the key in `log-key.xy.b64` is trusted as shipped." It says
out loud what the previous section explains at length, every single time,
so a reader of one result never has to have read this document first.

**Exit codes (`verify --self`):** `0` PASS, `1` FAIL, `2` `fixtures/self/` is
absent — the normal state for any checkout that is not itself the published
tarball, reported as "this checkout was not produced by a release; run the
release rehearsal or use a published tarball" rather than a stack trace. The
`verify_self` MCP tool returns the same message as a tool error
(`isError: true`, no `structuredContent`) rather than throwing.

**Tamper matrix**, from `test/core/verify-self.test.ts` against the frozen
bundle (`test/fixtures/self-bundle/`):

| Tamper                                             | `ok`    | Reported at                                           | `self.*`                                                     |
| -------------------------------------------------- | ------- | ----------------------------------------------------- | ------------------------------------------------------------ |
| none                                               | `true`  | —                                                     | `statementSignature: "ok"`, `payloadMatchesProvenance: true` |
| one byte of `provenance.json`                      | `false` | `stage: "binding"`, `reason: "self_payload_mismatch"` | `payloadMatchesProvenance: false`                            |
| one byte of `statement.cose`                       | `false` | `stage: "signature"`, `reason: "signature_invalid"`   | —                                                            |
| one byte of `receipt.cbor`'s signature             | `false` | `stage: "signature"`, `reason: "signature_invalid"`   | —                                                            |
| a different (but validly-encoded) `log-key.xy.b64` | `false` | `stage: "signature"`, `reason: "known_key_mismatch"`  | `statementSignature: "failed"`                               |
| explicit `genesis` root, untouched bundle          | `false` | `stage: "signature"`, `reason: "delegation_invalid"`  | `statementSignature: "ok"`, `payloadMatchesProvenance: true` |

The `provenance.json` row is the one worth reading twice: the receipt and
statement are untouched, so the mechanical receipt check still PASSES — it
is `verifySelf`'s own byte-for-byte comparison in step 2 above that catches
a caller holding the wrong `provenance.json` next to a genuine receipt, and
that closes the result to `FAIL` rather than reporting a mechanical PASS
that would be true and misleading at once.

## Secrets and variables (`npm-publish` environment)

| Name                        | Kind                | Purpose                                                                                                                                                                                                                                                                                                                    |
| --------------------------- | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `FORESTRIE_BASE_URL`        | variable            | SCRAPI origin for the lane, e.g. `https://api-a.forest-2.forestrie.dev`                                                                                                                                                                                                                                                    |
| `FORESTRIE_LOG_ID`          | variable            | The forest's root/bootstrap log id — **confirmed** in provisioning, not the publications log's own id. Used both as `register --log-id`'s URL segment and as the genesis fetch path segment. The grant, not this variable and not the bundle, is what names the publications log — see below.                              |
| `FORESTRIE_RELEASE_KEY_PEM` | secret              | ES256 private key, PEM. Written to a `0600` temp file for the one `sign-statement` invocation and deleted immediately after, real run or rehearsal alike. Its public point is also derived and bundled as `log-key.xy.b64` (see "The grant chain" above).                                                                  |
| `FORESTRIE_GRANT_B64`       | secret              | The completed `Authorization: Forestrie-Grant` credential, base64. `grant.logId` inside it — never `FORESTRIE_LOG_ID`, never the bundle — is the actual target: the publications log, a grandchild of the forest root.                                                                                                     |
| `FORESTRIE_CLI`             | variable (optional) | Path to a `forestrie` binary. When unset, the script downloads and sha256-verifies the same pinned `v0.7.0` release binary `test/differential/cli-binary.ts` uses (it already has `sign-statement` and `register` — confirmed via `--help`). Set this once `@forestrie/forestrie-cli` publishes to npm and CI installs it. |

## Rehearsal (plan-2609-02 step 2.6)

Run the `Publish` workflow via `workflow_dispatch` with `rehearsal: true`.
Every step up to and including `Pack` runs for real, against whatever lane
`FORESTRIE_BASE_URL` names — registration included — but the final `npm
publish` step is skipped, so nothing ships.

`scripts/assert-publish-version.sh` (the "Assert publish version
discipline" step, which runs first and fails the whole dispatch if it
fails) reads `REHEARSAL` from the environment and, on a rehearsal dispatch,
**skips its "not already on the registry" check entirely** — it prints `OK:
rehearsal dispatch for <name>@<version>; registry check skipped because
nothing is published` and exits 0 before ever calling `npm view`. That check
exists for a **recovery** dispatch, which does publish; a rehearsal never
does, so re-rehearsing an already-shipped version (the normal case, not an
error) must not trip it. The guard also refuses `REHEARSAL=true` on a tag
ref outright, belt and braces on top of the `Publish` step's own `if:` — a
tag build publishes by definition and can never be a rehearsal.

Checklist:

1. Confirm `GET {FORESTRIE_BASE_URL}/api/health` is clean (Blocker A, the
   Cloudflare quota, must be resolved first).
2. Confirm the owner has provisioned a lane-A publications log the same way
   as step 2.1's lane-B posture: a fresh ES256 key as the log's own owner
   key, `FORESTRIE_RELEASE_KEY_PEM` set to its private PEM.
3. Confirm `FORESTRIE_LOG_ID` is the **forest's root/bootstrap log id** for
   the lane being rehearsed, not the publications log's own id — see "The
   genesis question" above. Confirmed for lane A already; re-check for any
   new lane (lane B, when it is provisioned). If registration fails with a
   genesis-not-found style error, or the fetched `genesis.cbor` does not
   decode under `decodeTrustRootFromGenesis`, that is the first thing to
   check.
4. Dispatch with `rehearsal: true`. On success, download the `fixtures/self/`
   bundle from the run's workspace (or inspect the job log) and confirm
   `manifest.json`'s sha256 entries match the shipped files.
5. `node scripts/self-register.mjs --dry-run` (no env vars, no network, no
   CLI) is a **different**, purely local check — it proves the script's own
   control flow, not the lane. Do not treat a clean dry run as rehearsal
   evidence.

## The two trust roots, and why the loop does not close on itself

A tarball cannot contain a receipt over its own digest — the receipt would
have to be written before the tarball that carries it exists, and the
tarball's digest changes the moment the receipt is added to it. This package
does not try to close that loop; it uses two independent trust roots
instead. The **Forestrie receipt** binds `provenance.json` — which names the
release's `gitCommit` — into a transparency log at registration time;
`verify_self` (steps 2.4/2.5) proves that offline. **npm's SLSA provenance**,
already attested on every `@forestrie/*` publish, independently binds the
published tarball to that same `gitCommit` and the workflow that built it;
`npm audit signatures` proves that. Neither root depends on the other, and
together they say: _this_ tarball came from _this_ commit, and Forestrie's
log recorded a statement naming that commit at a given sequence position. The
root of trust is the univocity checkpoint the receipt chains to, not the
package — the package supplies the arithmetic, which any independent
implementation can re-run.

## Lane A today, lane B later

D4's target state is a dedicated, durable **lane B** publications log. Phase
2 proves the mechanism out on **lane A** instead (the owner's 2026-09-12
decision) — lane A is the rehearsal/dev lane, not the durable one. Every
receipt shipped in a 0.2.x tarball chains to a **dev-lane checkpoint**, not a
lane-B one, until a lane-B publications log is provisioned and this
package's secrets move to it. Moving lanes is a re-registration for future
releases, never a break for receipts already shipped — each receipt is
self-contained and keeps verifying against the checkpoint chain it was sealed
into, regardless of which lane later releases use.
