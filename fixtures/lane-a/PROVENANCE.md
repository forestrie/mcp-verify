# lane-A anchored bundle — a real receipt and the real accumulator, frozen

The one bundle in this package under which an **accumulator root runs
offline against an independent anchor**. The golden vectors ship no
accumulator snapshot (the `demo` derives one from the receipt's own peak
and says so); the burial bundle ships a checkpoint chain but not the leaf
preimage its receipt needs. This directory ships both halves of a real
pair: a receipt from a public lane, and the accumulator the univocity
contract had published for that log, captured by an independent chain
read.

| File | What it is | Where it came from |
|---|---|---|
| `receipt.cbor` (438 B) | the receipt for `@forestrie/mcp-verify` 0.4.0's own release-time self-registration | `GET https://api-a.forest-2.forestrie.dev/logs/67876864-3b46-67ae-dcb3-13cc81624aa5/e8345800-a747-4e62-9409-61622b836f1f/14/entries/a09a6337ee0009000000000000000008/receipt`, 2026-09-13T14:23:08Z |
| `statement.cose` | the signed statement that receipt commits (payload: 0.4.0's `provenance.json`) | the published `@forestrie/mcp-verify@0.4.0` tarball, `fixtures/self/statement.cose` |
| `entry-id.txt` | `a09a6337ee0009000000000000000008`: idtimestamp ‖ mmrIndex 8 | the same tarball's `fixtures/self/entry-id.txt`; also what the lane's registration-status 303 named |
| `log-key.xy.b64` | the publications log owner's public key, P-256 x‖y | the same tarball's `fixtures/self/log-key.xy.b64` (byte-identical across 0.4.0 and 0.4.1) |
| `genesis.cbor` (160 B) | the forest genesis document binding chain 84532 and univocity `0x678768643b4667aedcb313cc81624aa560b7f0ca` | `GET https://api-a.forest-2.forestrie.dev/api/forest/67876864-3b46-67ae-dcb3-13cc81624aa5/genesis`, 2026-09-13T14:22:52Z |
| `accumulator.cbor` (213 B) | `encodeKnownAccumulator` snapshot of the log's published state: size 11, three peaks, at block 46770471 (hash `0x713c531b…91e170`) | three JSON-RPC calls (`eth_chainId`, `eth_getBlockByNumber latest`, `eth_call logState(logId)`) made once on 2026-09-13 to a Base Sepolia RPC endpoint the maintainer supplied; the raw exchange is frozen in `forestrie/mcp-resolve`'s `test/fixtures/chain/logState.46770471.json` and this snapshot is that package's `fetch_accumulator` output over it |

These bytes are **FROZEN**. `manifest.json` carries their sha256 and the
coordinates above; `test/core/golden-pin.test.ts` pins every file. They
are the same bytes `forestrie/mcp-resolve` freezes under
`test/fixtures/lane-a/` and `test/fixtures/chain/` (see the
`PROVENANCE.md` in each), copied here so the verifier's tarball can offer
them as `forestrie://fixtures/lane-a/…` resources.

## What the pair proves, and what it does not

`verify_receipt` over `receipt.cbor`, `statement.cose` and `entry-id.txt`
under `{root: "known-accumulator", accumulator: accumulator.cbor}` passes
with **split-view ok**: the receipt's recomputed peak is one of the three
peaks the contract published at size 11. That is a real anchor — the
contract's state, read from the chain, not derived from the receipt — so
unlike the `demo`'s self-derived snapshot it is evidence, not a
self-consistency check.

It is evidence **as of block 46770471**. The log has grown since; the
latest `logState` may have folded that peak into a bigger one, which is
why a live check uses `@forestrie/mcp-resolve`'s history look-back. A
kept snapshot answers split-view for the receipts whose peaks it holds,
for as long as you keep it — that is the point of keeping one.

The same receipt under `{root: "known-log-key", keyXy: log-key.xy.b64}`
passes (sealing, attribution); under `{root: "genesis", genesis:
genesis.cbor}` it reports `delegation_invalid`, because the publications
log is a grandchild of the forest root and the genesis root's offline
walk resolves one hop (docs/self-registration.md).

## Regeneration

A deliberate act, never a fix for a red test: capture a new receipt and
a new chain read, replace the whole directory, update `manifest.json`,
and say so in this file. The receipt and statement pair with 0.4.0's
release only; a later release's `fixtures/self/` is a different entry.
