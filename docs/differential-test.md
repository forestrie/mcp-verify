# The differential test

The only test that proves _"agrees with the reference exactly"_. Everything
else in this repo proves that our arithmetic is self-consistent; this proves it
is the same arithmetic somebody else already ships.

```
pnpm test:differential
```

Not part of `pnpm test`, because it fetches an npm package over the network
and `pnpm test` stays hermetic. CI runs it as its own job so a registry outage
is a distinguishable red rather than a mysterious unit-test failure.

## How the reference is obtained

**The published npm package, resolved at a pinned exact version and run under
plain `node`.** Not a source checkout, not Bun, and — since plan-2609-02
workstream P step P5 — no longer a downloaded binary either.

|                                         |                                  |
| --------------------------------------- | -------------------------------- |
| Pinned version                          | `@forestrie/forestrie-cli@0.8.0` |
| `@forestrie/receipt-verify` it resolves | `1.0.0` — same as this package   |
| `@forestrie/encoding` it resolves       | `0.7.0` — same as this package   |

Resolution order (`test/differential/cli-binary.ts`):

1. `$FORESTRIE_CLI_BIN`, if set. Deliberately **not** version-checked: an
   override is an explicit local decision to test against something else
   (a locally built binary, a dev checkout's compiled entry point, …), and
   silently refusing it would make bisecting a divergence impossible. Run
   directly. The test warns when it is in use.
2. `npm install --no-save --prefix node_modules/.cache/forestrie-cli-npm/<version>
@forestrie/forestrie-cli@<version>`, once per pinned version — the install
   is skipped on every subsequent run once that directory exists, and a
   version bump gets a fresh install by construction because the cache path
   is keyed on the version. `--no-save --prefix` means this **never** touches
   this repo's own `package.json` or pnpm lockfile: `@forestrie/forestrie-cli`
   is not, and must not become, a dependency of this package for the
   differential test alone.
3. The installed `dist/cli.js` is run as `node <entry> <args>` — under the
   same node binary running the test, not execed directly — so this works
   identically on linux, darwin and Windows. There is no per-platform binary
   matrix to skip any more: the linux-arm64, darwin-x64 and Windows skips this
   file used to carry are gone.

An npm install failure **never** falls back to running anyway — an
unresolvable reference is a skip (or, in CI, a hard failure), never a
differential run against something unpinned.

`FORESTRIE_DIFFERENTIAL=required` (set in CI) turns an unresolvable reference
into a hard failure. Locally you get a clean skip with a one-line reason.

### Why npm and not a source checkout

1. It is literally what an outside auditor runs (`npx -y
@forestrie/forestrie-cli`) — the neutrality property the whole plan is
   about.
2. It removes Bun from this repo entirely, CI included. The toolchain is mise
   node + pnpm and nothing else, and "does the toolchain contain Bun" has a
   one-word answer.
3. `@forestrie/forestrie-cli@0.8.0` resolves the same `@forestrie/receipt-verify`
   (1.0.0) and `@forestrie/encoding` (0.7.0) as this package — the version-skew
   this file used to carry as a triage category is gone, not merely pinned
   around.
4. A source checkout would need building someone else's repo from source
   before every CI run and pinning a lockfile for it; the published package is
   what an outsider actually installs.

The cost: the pin tracks _released_ behaviour, not an arbitrary commit. That is
a feature — released behaviour is what an outsider can reproduce. There is no
checksum sidecar the way a GitHub release binary had one; the pin is now the
exact `FORESTRIE_CLI_VERSION`, and npm's own registry-integrity check (an
integrity hash in the registry metadata, verified by npm on every install) is
what stands in for the sha256 sidecar this file used to check by hand.

## What is compared

For each of the seven variants (`clean` plus the six tampers, generated
in-test, never committed as files) × the two signature roots (`genesis`,
`known-log-key`):

1. Materialise the bytes into a `mkdtemp` dir — the CLI is file-oriented.
2. `forestrie verify-grant --json --genesis … --receipt … --committed-grant-file … --entry-id …`
3. Our `verifyGrantReceipt()` over the same bytes.
4. Assert `ok`, `stage`, `reason` and `stages` deep-equal — the four fields the
   CLI's `VerifyReport` names as a contract, which its own CI asserts. Exit
   code is checked too.

`questions`, `diagnostics` and `verifier` are **ours alone** and are not
compared. They are a superset, not a divergence.

Plus `decode_receipt` against `forestrie decode-receipt --json`, over the
golden receipt and the burial receipt, as a **full deep-equal of the JSON
documents**.

### Current status

Last run 2026-09-13 on darwin-arm64 against `@forestrie/forestrie-cli@0.8.0`
from npm: **18 tests, zero disagreements.**

That includes the decode comparison, which is worth dwelling on, because
`src/core/decode-receipt.ts` is a _fresh implementation_ over the published
packages rather than a copy of the CLI's source. It was written to a documented
subset and turned out to reproduce the reference output exactly — nested CBOR
rendering of header 396 included. The assertion started as a subset match and
was strengthened to a deep-equal only once the runtime showed it held.

## The two accumulator roots deliberately outside the matrix

`known-accumulator` and `checkpoint-chain` are **not** compared, and this is a
design difference rather than a disagreement:

`forestrie verify --known-accumulator` runs the genesis/known-key offline
verify **first**, and checks the anchor only if that passed. So the
detached-payload stage collapse survives into its accumulator check: a path tamper
still reports `signature_invalid` there.

Here, `known-accumulator` is a **standalone** root — the accumulator is the
sole authority, no signature is evaluated, and a path tamper reports
`peak_not_in_known_accumulator` with `split-view: failed`. That is what
produces the separation the whole package exists to demonstrate, and it is
what the `TrustRoot` input union describes: the `known-accumulator` variant
takes no genesis and no key.

Comparing them would be comparing two different questions. Recorded here rather
than papered over, and asserted on our side in
`test/core/root-table.test.ts`. See [trust-roots.md](trust-roots.md).

## Cases deliberately not in the matrix

`verify-grant` with neither `--committed-grant` nor `--committed-grant-file`
crashes with an uncaught stack trace, **even under `--json`**. Comparing
against a stack trace proves nothing, so the case is excluded here; our own
clean validation error is asserted in
`test/core/verify-grant-receipt.test.ts`, and the CLI bug is filed separately.
This is the reason the MCP layer validates its own inputs rather than trusting
the reference to fail cleanly.

## When a cell disagrees

**A disagreement is a finding, not a test bug.** Triage it as exactly one of:

| Verdict     | What to do                                                                                 |
| ----------- | ------------------------------------------------------------------------------------------ |
| **our bug** | Fix our code. Most likely outcome; assume this first.                                      |
| **CLI bug** | Pin the expectation here with a comment naming the bug and linking the issue, and file it. |

The version-skew row this table used to carry (`receipt-verify` 0.9.0 vs
1.0.0) is retired: `@forestrie/forestrie-cli@0.8.0` resolves the same
`@forestrie/receipt-verify` (1.0.0) and `@forestrie/encoding` (0.7.0) as this
package, so that category of disagreement no longer applies. If a future CLI
release reintroduces a skew, add the row back with the two versions named.

**Never silently loosen an assertion.** A `toMatchObject` where a `toEqual`
used to be, with no comment, is how a differential test becomes decorative. If
you weaken one, say what diverged and why, here and in the test.

## Rebasing the pin

When `forestrie-cli` cuts a new npm release, this is a version bump, nothing
more:

1. `npm view @forestrie/forestrie-cli versions --json` — confirm the new
   version is actually published.
2. Edit `FORESTRIE_CLI_VERSION` in `test/differential/cli-binary.ts`. The
   install cache is keyed on this constant, so the bump gets a fresh `npm
install` by construction; nothing to delete by hand.
3. Update the `key:` of the cache step in `.github/workflows/ci.yml` if it
   names the version (it does — that is what invalidates CI's cache on a
   bump).
4. Update the table at the top of this file.
5. Run `pnpm test:differential`. Triage every new disagreement per the table
   above **before** merging. A rebase that turns cells red and gets merged
   with the assertions relaxed is worse than not rebasing.

Bump deliberately. The pin is the point: it is what makes "agrees with the
reference" a statement about a specific, published, exact-version artefact
rather than about whatever happened to be on `main` that day.
