# Self-registration

Every release registers a small binding document in a Forestrie transparency
log, and ships the receipt inside the tarball it describes. This is
plan-2609-02 step 2.3; the tool that verifies the bundle offline
(`verify_self` / `verify --self`) is step 2.4, not yet implemented — the
`forestrie://self/…` MCP resource namespace exists in `src/node/server.ts`
today only as a reservation.

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
5. Bundles all of it under `fixtures/self/`: `provenance.json`,
   `statement.cose`, `receipt.cbor`, `genesis.cbor`, `entry-id.txt`, and a
   `manifest.json` carrying the sha256 of each.

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
env var is needed. The one thing that evidence trail cannot settle from
source alone: whether the value the owner provisions into `FORESTRIE_LOG_ID`
really is the forest's bootstrap id (as opposed to the publications log's own
id, which is a different value once `create-log` has run). **That is a
rehearsal check, not a code question** — see below.

## Secrets and variables (`npm-publish` environment)

| Name                        | Kind                | Purpose                                                                                                                                                                                                                                                                                                                    |
| --------------------------- | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `FORESTRIE_BASE_URL`        | variable            | SCRAPI origin for the lane, e.g. `https://api-a.forest-2.forestrie.dev`                                                                                                                                                                                                                                                    |
| `FORESTRIE_LOG_ID`          | variable            | The forest's bootstrap log id — used both as `register --log-id`'s URL segment and as the genesis fetch path segment. Confirm this in rehearsal (above).                                                                                                                                                                   |
| `FORESTRIE_RELEASE_KEY_PEM` | secret              | ES256 private key, PEM. Written to a `0600` temp file for the one `sign-statement` invocation and deleted immediately after, real run or rehearsal alike.                                                                                                                                                                  |
| `FORESTRIE_GRANT_B64`       | secret              | The completed `Authorization: Forestrie-Grant` credential, base64. Carries the actual target (publications) log id inside it.                                                                                                                                                                                              |
| `FORESTRIE_CLI`             | variable (optional) | Path to a `forestrie` binary. When unset, the script downloads and sha256-verifies the same pinned `v0.7.0` release binary `test/differential/cli-binary.ts` uses (it already has `sign-statement` and `register` — confirmed via `--help`). Set this once `@forestrie/forestrie-cli` publishes to npm and CI installs it. |

## Rehearsal (plan-2609-02 step 2.6)

Run the `Publish` workflow via `workflow_dispatch` with `rehearsal: true`.
Every step up to and including `Pack` runs for real, against whatever lane
`FORESTRIE_BASE_URL` names — registration included — but the final `npm
publish` step is skipped, so nothing ships.

Checklist:

1. Confirm `GET {FORESTRIE_BASE_URL}/api/health` is clean (Blocker A, the
   Cloudflare quota, must be resolved first).
2. Confirm the owner has provisioned a lane-A publications log the same way
   as step 2.1's lane-B posture: a fresh ES256 key as the log's own owner
   key, `FORESTRIE_RELEASE_KEY_PEM` set to its private PEM.
3. Confirm `FORESTRIE_LOG_ID` is the **forest's bootstrap log id** for lane
   A, not the publications log's own id — see "The genesis question" above.
   If registration fails with a genesis-not-found style error, or the
   fetched `genesis.cbor` does not decode under
   `decodeTrustRootFromGenesis`, that is the first thing to check.
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
`verify_self` (step 2.4) will prove that offline. **npm's SLSA provenance**,
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
