# Fixture provenance

Everything under `fixtures/golden/` is **frozen bytes**, copied byte-for-byte
from the `@forestrie/receipt-verify` golden vectors. Regeneration is a
deliberate act, never a casual fix for a red test.

## Source

| | |
|---|---|
| Repo | `forestrie/canopy` (public, MIT) |
| Commit | `314d13df4a686ecc0f6463844ccd74f06aacb546` |
| Path | `packages/libs/receipt-verify/test/fixtures/golden/` |
| Copied on | 2026-09-05 |
| Licence | MIT (the `@forestrie/receipt-verify` package declares MIT) |

The bytes are also identical to those at canopy
`1f199e8c9156200c06f8f455e277e4b032663c52`, an earlier commit —
the fixtures have not moved between those two commits, which is the whole
point of calling them frozen.

## Regenerated 2026-09-20 for the signed checkpoint tree size (ADR-0066)

Every file under `golden/` was replaced on 2026-09-20 with canopy's regenerated
set (canopy main at `d7e7a61`, landed by canopy #255, devdocs plan-2609-10
slice 04). A checkpoint now carries its sealed tree size under protected
label `-65933`, the consistency proof must have exactly the shape the two
sizes imply, and the protected header must be deterministic CBOR;
`@forestrie/receipt-verify` 2.0.0 rejects a checkpoint without the label.
The old bytes cannot be re-verified by the new library, so canopy
regenerated the grant goldens with a fresh signing key (the manifest's
`grantDataHex` changed with it) and the burial bundle with a new chain key
and low-s signatures. The manifests' comments record the same. This
package copied them byte-for-byte, as the rule below says, and nothing in
`src/` reads any value that moved except through the manifests.

## What is here

| File | What it is |
|---|---|
| `golden/manifest.json` | Golden conformance manifest. `genesisSha256` / `receiptSha256` are the pin; `logId` + `grantDataHex` + `idtimestampBe8Hex` are what the committed grant is reconstructed from. Copied **verbatim** — do not reformat. |
| `golden/grant-genesis.cbor` | 160 B forest-genesis document (schema v2, ES256 bootstrap key). The `genesis` root. |
| `golden/grant-receipt.cbor` | 118 B COSE receipt over a grant leaf. **Detached payload** — the signature covers the MMR peak, which is why the stage collapse in `docs/trust-roots.md` happens at all. |
| `golden/burial/manifest.json` | Burial-bundle manifest: public key, leaf, buried peak, final accumulator, per-checkpoint digests. |
| `golden/burial/burial-receipt.cbor` | A receipt whose peak the log has since buried. |
| `golden/burial/sth-000{0..3}.cbor` | The retained `.sth` checkpoint chain that re-anchors it. |

## Why they are at the repo root and not under `test/`

Upstream keeps them in `test/fixtures/golden/` and excludes `test/` from the
published tarball. Here they must **ship**: `npx @forestrie/mcp-verify demo`
and the `forestrie://fixtures/golden/…` MCP resources have to work from a
fresh install with no repo checkout. Root placement plus `fixtures` in
`package.json#files` is the smallest way to say that.

`.prettierignore` excludes `fixtures/` and `*.cbor`. Prettier rewriting
`manifest.json` would not break the `.cbor` digests, but it would create a
diff that looks like tampering — and the pin test would then be asserting
against a file someone's editor had touched.

## Regeneration

Upstream, not here:

```
# in a canopy checkout
pnpm --filter @forestrie/receipt-verify exec tsx scripts/export-golden-vectors.ts
pnpm --filter @forestrie/receipt-verify exec tsx scripts/export-burial-bundle.ts
```

Then copy the whole directory across again and update the commit hash above in
the same PR. `test/core/golden-pin.test.ts` fails until the digests and the
manifests agree, which is the point.

## The lane-A anchored bundle

`fixtures/lane-a/` is a third set: a real receipt from a public lane and
the accumulator the chain published for its log, frozen together so an
accumulator root runs offline against an independent anchor. It has its
own [PROVENANCE.md](lane-a/PROVENANCE.md) and manifest, and the same pin
test covers it.

## The self-registration bundle is a different thing, elsewhere

`fixtures/self/` (this package's own release-time self-registration bundle)
is **generated and gitignored** — never committed, so
there is nothing under it for this file to describe provenance for. What
`verify_self` / `verify --self` are tested against instead is
a REAL bundle captured once and frozen for tests at
[`test/fixtures/self-bundle/`](../test/fixtures/self-bundle/), with its own
provenance record at
[`test/fixtures/self-bundle/PROVENANCE.md`](../test/fixtures/self-bundle/PROVENANCE.md).
Read that file, not this one, before touching anything under it.

## What is NOT a fixture

The **committed grant** for the golden receipt is not a file. It is
reconstructed at runtime from `manifest.json` by `src/node/fixtures.ts`
(`goldenCommittedGrant()`), using the same field layout as canopy's
`test/helpers/grant-receipt-fixture.ts` `grantWithData()`. Reconstructing it
rather than freezing a ninth file keeps the manifest the single source of
truth, and `test/core/verify-grant-receipt.test.ts` proves the reconstruction
is right by verifying the frozen receipt against the frozen genesis with it.
