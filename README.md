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
| `verify_self`          | `forestrie verify`                | Does this package's own release receipt vouch for the bytes it ships?        |
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

## You do not have to trust the operator

A receipt means something without assuming the Forestrie operator is honest:

- **A pipe, not a store.** Only content hashes enter the log. Your statement
  and its receipt stay with you, and verification is pure over those bytes,
  so a check never has to ask the operator for anything.
- **The operator does not hold the authority.** A log's root key belongs to
  the log's owner, and the forest's bootstrap key to its curator. The
  operator's sealer holds only a short, scoped lease to sign checkpoints.
- **One published history.** Checkpoints are published to the univocity
  contract, which refuses any that are inconsistent with what it already
  holds. The accumulator roots above check against that.

An operator can still decline to act, and that is visible. It cannot forge,
rewrite or re-root a log. Who holds which key, and what an operator can and
cannot do:
[key custody](https://github.com/forestrie/protocol/blob/main/spec/key-custody-and-choice.md)
and
[operator powers](https://github.com/forestrie/protocol/blob/main/spec/trust-boundaries-and-operator-powers.md).

## This package's own provenance

Software provenance is the familiar use case for a transparency log, so this
package applies it to itself. Every release registers a small statement
(package name, version, git commit) in a Forestrie log and ships the receipt
inside the tarball. `npx -y @forestrie/mcp-verify verify --self`, or the
`verify_self` tool, checks it offline. This complements npm's SLSA
provenance; it does not replace it. Today the receipt chains to a development
lane log. Details: [docs/self-registration.md](docs/self-registration.md).

The verification arithmetic comes from `@forestrie/receipt-verify`, which is
published and attested separately, and is checked against the reference
`forestrie` CLI: [docs/differential-test.md](docs/differential-test.md).

## Registry

Once phase 3 lands, this server is listed as `dev.forestrie/verify` in the
[official MCP registry](https://registry.modelcontextprotocol.io).

## Development

```
mise install           # node 22.14.0, pnpm 10.6.5
pnpm install
pnpm test              # browser-safe gate + encoding-copy gate + server.json gate + unit tests
pnpm test:differential # npm-installs the pinned forestrie CLI version
pnpm build
```

Conventions, invariants and the release checklist: [AGENTS.md](AGENTS.md).
Dependency surface and install weight:
[docs/dependency-surface.md](docs/dependency-surface.md).

## Licence

MIT.
