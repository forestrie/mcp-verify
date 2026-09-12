# @forestrie/mcp-verify

An MCP server whose only tools verify and decode Forestrie receipts.
**No backend, no account, no key, no network.**

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

## Why

Agents act on statements they did not witness being made: a quote, an
approval, a tool result, another agent's output. Usually the record of what
was said is kept by the party that said it, so nobody downstream can ask
"did you really say that, and did you say it to everyone?"

A Forestrie receipt is a proof that a statement was sealed into an
append-only transparency log. This package checks that proof against a trust
root you hold, in your own process, without contacting Forestrie. With the
right root it also answers the harder question: whether the log you were
shown is the log everyone else was shown. What transparency adds, where it
stops, and what a receipt contains: [TRANSPARENCY.md](TRANSPARENCY.md).

## What it proves

| Tool                   | Reference verb                    | What it answers                                                              |
| ---------------------- | --------------------------------- | ---------------------------------------------------------------------------- |
| `verify_receipt`       | `forestrie verify`                | Were these exact payload bytes sequenced at this entry id?                   |
| `verify_grant_receipt` | `forestrie verify-grant`          | Was this grant admitted to this log — i.e. was the signer entitled to write? |
| `decode_receipt`       | `forestrie decode-receipt --json` | What is actually in this receipt? (Renders the CBOR only. Verifies nothing.) |

Every tool is annotated `readOnlyHint: true, openWorldHint: false`. That is
not decoration: it is the machine-readable form of _"this tool touches
nothing"_, and an agent can see it without running anything.

## Trust roots

You do not ask for "verification". You say which root you trust, and the
result says what that root can see:

| Root                | What you supply                                             |
| ------------------- | ----------------------------------------------------------- |
| `genesis`           | the forest's genesis document, captured when you registered |
| `known-log-key`     | a log owner key you hold out of band                        |
| `known-accumulator` | a snapshot of the log's peaks, from a chain read            |
| `checkpoint-chain`  | a retained chain of `.sth` checkpoints                      |

The roots are not ordered by strength. The first two check the operator's signature
locally and cannot see a split view. The last two match the peak against an
accumulator the operator does not control, and can. Every result answers
four questions, **sealing**, **split-view**, **append-authority** and
**attribution**, each `ok`, `failed`, or `not_answered_by_this_root`. The
last is a real answer and must reach the user; a client that renders only
`ok` is using this tool wrong.

When each root is the effective choice, why a genesis document fetched at
check time is weaker than one kept from registration, what a signature root
cannot distinguish, and the demo transcript:
[docs/trust-roots.md](docs/trust-roots.md).

## Not a trust circle

> The root of trust is the univocity checkpoint the receipt chains to, not the
> package; the package supplies the arithmetic, which any independent
> implementation can re-run.

Which is why this repo goes to some trouble to make that re-running possible:

- **A differential test** against the published, sha256-pinned `forestrie`
  release binary. For every tamper variant under both signature roots, our `ok`,
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

## Development

```
mise install           # node 22.14.0, pnpm 10.6.5
pnpm install
pnpm test              # browser-safe gate + encoding-copy gate + unit tests
pnpm test:differential # needs the pinned forestrie CLI binary
pnpm build
```

Conventions, invariants and the release checklist: [AGENTS.md](AGENTS.md).
Dependency surface and install weight:
[docs/dependency-surface.md](docs/dependency-surface.md).

## Licence

MIT.
