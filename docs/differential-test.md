# The differential test

This test compares mcp-verify's verification with an independent reference, the
published `@forestrie/forestrie-cli`. Every other test in this repo shows that
the arithmetic is consistent with itself. This one shows that it gives the same
answers as a verifier someone else ships.

Read this document for three things:

- exactly what "agrees with the reference" covers, and what it does not;
- what to do when a comparison disagrees;
- how to move the reference to a new version.

## What is compared

**Grant receipt verification.** Seven variants of the golden grant receipt,
the clean receipt plus six tampers generated inside the test, are each verified
under the two signature roots, `genesis` and `known-log-key`. For each one, the
test writes the bytes to a temporary directory, runs
`forestrie verify-grant --json` on them, and runs `verifyGrantReceipt()` on the
same bytes. It requires `ok`, `stage`, `reason` and `stages` to be equal, and
the CLI's exit code to match. Those four fields are the contract the CLI's
`VerifyReport` names.

**Receipt decoding.** `decode_receipt` output must equal
`forestrie decode-receipt --json` exactly, as whole JSON documents, for the
golden receipt and the burial receipt. This comparison means something only
because mcp-verify's renderer is a separate implementation, written over the
same published packages rather than taken from the CLI. Delegating to the CLI's
decoder would turn it into a comparison of one implementation with itself.
[AGENTS.md](../AGENTS.md) records why that has not been done.

## What is not compared

- **The trust-question answers, diagnostics and version report.** `questions`,
  `diagnostics` and `verifier` exist only in mcp-verify, so there is nothing to
  compare them with.
- **The `known-accumulator` and `checkpoint-chain` roots.** They answer a
  different question from the CLI's `--known-accumulator` option. The CLI runs
  the signature check first and consults the accumulator only if that passes,
  so a tampered inclusion path still fails as `signature_invalid`. Here the
  accumulator is the only authority and no signature is checked, so the same
  tamper fails as `peak_not_in_known_accumulator`, with split-view `failed`.
  mcp-verify's side is asserted in `test/core/root-table.test.ts`. See
  [trust-roots.md](trust-roots.md).
- **`verify-grant` with no committed grant.** The CLI crashes with a stack
  trace, even with `--json`, so there is no output to compare. mcp-verify's own
  validation error is asserted in `test/core/verify-grant-receipt.test.ts`, and
  the CLI bug is filed.
- **A non-canonical protected header.** This is the one known behavioural
  difference. mcp-verify decodes the protected header strictly and refuses a
  non-canonical one, while the CLI renders it. No fixture carries such a
  header.

## Which reference, exactly

The reference is `@forestrie/forestrie-cli` from npm, at the exact version set
by `FORESTRIE_CLI_VERSION` in `scripts/forestrie-cli-npm.mjs`. The test finds
it in this order:

1. `FORESTRIE_CLI_BIN`, if set. This is for deliberately testing against
   something else, such as a local build, so it is not version-checked, and the
   test warns when it is used.
2. Otherwise, an `npm install --no-save` of the pinned version into
   `node_modules/.cache/forestrie-cli-npm/<version>`, done once and then
   reused. It never changes this repo's `package.json` or lockfile:
   `@forestrie/forestrie-cli` must not become a dependency of this package.
3. The installed CLI runs under the same `node` as the test, so it behaves the
   same on every platform.

If the reference cannot be resolved, the test skips locally and fails in CI,
where `FORESTRIE_DIFFERENTIAL=required` is set. It never runs against an
unpinned reference.

Only the CLI's own version is pinned. The CLI resolves its
`@forestrie/receipt-verify` and `@forestrie/encoding` from its declared version
ranges when it is installed, and that install is cached per CLI version,
locally and in CI. The reference can therefore run older library versions than
the exact versions this package pins, until the cache is rebuilt.

npm is used rather than a source checkout because it is what an outside auditor
runs, `npx @forestrie/forestrie-cli`, and because it keeps Bun out of the
toolchain. npm's registry integrity check stands in for a checksum pin.

## Running it

```
pnpm test:differential
```

It is not part of `pnpm test`, which never touches the network. CI runs it on
every pull request as its own job, "Differential vs forestrie CLI", so a
registry outage shows up as a separate failure. That job is the current status.

## When a comparison disagrees

A disagreement is a finding, not a test bug. Decide which of these it is:

- **A bug in mcp-verify.** Fix the code. Assume this first.
- **A bug in the CLI.** Pin the CLI's output in the test with a comment that
  names the bug and links the issue, and file it.
- **Different library versions.** Compare the `@forestrie/*` versions inside
  the cached reference install with this package's pins. Rebuild the cache, or
  record both versions in the test, before calling it a bug on either side.

Never loosen an assertion silently. If one has to change, say what diverged and
why, in the test and in this document.

## Moving the reference to a new version

1. Confirm the new version is published:
   `npm view @forestrie/forestrie-cli versions --json`.
2. Change `FORESTRIE_CLI_VERSION` in `scripts/forestrie-cli-npm.mjs`. It is the
   only place the version lives, shared with `scripts/self-register.mjs`, and
   the install cache path includes it, so the next run installs afresh.
3. Change the version in the cache step's `key:` in `.github/workflows/ci.yml`,
   so CI stops reusing the old install.
4. Run `pnpm test:differential` and settle every new disagreement before
   merging. Never merge a bump with assertions relaxed to make it pass.
5. Compare the CLI's label tables with the ones in `src/core/decode-receipt.ts`
   by hand. The decode comparison notices a wording change only for a codepoint
   a fixture carries, and no fixture carries the Forestrie private-use
   codepoints. Both tables should follow the
   [forestrie/protocol label registry](https://github.com/forestrie/protocol/blob/main/spec/label-registry.md).
