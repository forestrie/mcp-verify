# self-bundle — a real release-time self-registration bundle, frozen

Produced on 2026-09-12 by `scripts/self-register.mjs` run against lane A
(`https://api-a.forest-2.forestrie.dev`) from `main` at 62c31ad, with the
release key as the publications log's owner. The publications log is
`e8345800-a747-4e62-9409-61622b836f1f`, a child of auth log
`04978814-4e41-4fc6-a896-9374b104ff42` under forest root
`67876864-3b46-67ae-dcb3-13cc81624aa5`; `genesis.cbor` is that forest's
genesis document. The registered entry is the one named in `entry-id.txt`.

These bytes are FROZEN test fixtures for `verify_self` / `verify --self`
(plan-2609-02 steps 2.4 and 2.5). `manifest.json` carries their sha256;
`test/core/golden-pin.test.ts`-style pinning applies. Regenerate only by
running the script again against a lane and replacing the whole directory.

Verified at capture with `forestrie verify --known-log-key <log-key.xy.b64>
--receipt receipt.cbor --payload provenance.json --entry-id <entry-id.txt>`:
PASS. Under `--genesis` the same receipt reports `delegation_invalid`: the
genesis root vouches for the forest root log only, and nothing walks the
grant chain to a child log yet. Nothing here is secret: the key is public,
the grant is not included.
