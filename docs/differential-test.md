# The differential test

The only test that proves _"agrees with the reference exactly"_. Everything
else in this repo proves that our arithmetic is self-consistent; this proves it
is the same arithmetic somebody else already ships.

```
pnpm test:differential
```

Not part of `pnpm test`, because it fetches a ~100 MB binary and `pnpm test`
stays hermetic. CI runs it as its own job so a GitHub-release outage is a
distinguishable red rather than a mysterious unit-test failure.

## How the reference is obtained

**The published, sha256-pinned GitHub release binary.** Not a source checkout,
not Bun.

`forestrie-cli` at v0.7.0 is `private: true` on npm and ships static binaries
on GitHub Releases, each with a `.sha256` sidecar. So:

|                          |                                                                    |
| ------------------------ | ------------------------------------------------------------------ |
| Pinned tag               | `v0.7.0`, published 2026-08-22                                     |
| `forestrie-darwin-arm64` | `a0b68282b39e491382051e2d496e677e35fd5ff814888a5fbf101d27bd0d175b` |
| `forestrie-linux-x64`    | `f211de74dc7944fb15ab652efddd0a9d6517239adea9c98cb0dd20484eccc1ed` |

Both digests were confirmed against the release's own `.sha256` sidecars **and**
GitHub's asset digests — two independent witnesses for the same bytes.

Resolution order (`test/differential/cli-binary.ts`):

1. `$FORESTRIE_CLI_BIN`, if set. Deliberately **not** checksum-checked: an
   override is an explicit local decision to test against something else, and
   silently refusing it would make bisecting a divergence impossible. The test
   warns when it is in use.
2. A cached copy under `node_modules/.cache/forestrie-cli/<tag>/`, re-hashed
   every run.
3. Download, verify sha256, cache, `chmod +x`.

A digest mismatch **never** falls back to running anyway. A differential run
against unverified bytes proves nothing and is worse than not running.

`FORESTRIE_DIFFERENTIAL=required` (set in CI) turns an unresolvable binary into
a hard failure. Locally you get a clean skip with a one-line reason. There is
no release asset for linux-arm64, darwin-x64 or Windows, so those hosts skip.

### Why a binary and not the source

The original plan said "CLI exported at a pinned tag, run via Bun in CI". This deviates, deliberately:

1. It removes Bun from this repo entirely, CI included. The toolchain is mise
   node + pnpm and nothing else, and "does the toolchain contain Bun" has a
   one-word answer.
2. A sha256 sidecar is a **checksum** pin, strictly stronger than a git tag,
   which can be moved.
3. It is literally what an outside auditor would run — the neutrality property
   the whole plan is about.
4. A source checkout would need `bun install` against `receipt-verify ^0.9.0`,
   which is the very skew the differential exists to expose, and pinning a
   lockfile for someone else's repo is not maintainable.

The cost: the pin tracks _released_ behaviour, not an arbitrary commit. That is
a feature — released behaviour is what an outsider can reproduce.

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

Last run 2026-09-06 on darwin-arm64 against `v0.7.0`: **18 tests, zero
disagreements.**

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

| Verdict          | What to do                                                                                                                        |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| **our bug**      | Fix our code. Most likely outcome; assume this first.                                                                             |
| **CLI bug**      | Pin the expectation here with a comment naming the bug and linking the issue, and file it.                                        |
| **version skew** | The CLI at v0.7.0 resolves `receipt-verify` **0.9.0**; we use **1.0.0**. Pin with a comment naming the skew and the two versions. |

**Never silently loosen an assertion.** A `toMatchObject` where a `toEqual`
used to be, with no comment, is how a differential test becomes decorative. If
you weaken one, say what diverged and why, here and in the test.

## Rebasing the pin

When forestrie-cli cuts a new release:

1. `gh release view vX.Y.Z -R forestrie/forestrie-cli --json assets` — confirm
   the asset names have not changed.
2. Fetch both `.sha256` sidecars and cross-check them against the `digest`
   field GitHub reports for each asset. Two witnesses, not one.
3. Update `CLI_TAG` and `CLI_SHA256` in `test/differential/cli-binary.ts`, and
   the `key:` of the cache step in `.github/workflows/ci.yml` — the cache key
   names the tag so a bump invalidates it by construction.
4. Update the table at the top of this file.
5. Run it. Triage every new disagreement per the table above **before**
   merging. A rebase that turns cells red and gets merged with the assertions
   relaxed is worse than not rebasing.

Bump deliberately. The pin is the point: it is what makes "agrees with the
reference" a statement about a specific, downloadable, checksummed artefact
rather than about whatever happened to be on `main` that day.
