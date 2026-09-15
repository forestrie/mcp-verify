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

## Not a trust circle

> The root of trust is the univocity checkpoint the receipt chains to, not the
> package; the package supplies the arithmetic, which any independent
> implementation can re-run.

Which is why this repo goes to some trouble to make that re-running possible:

- **A differential test** against `@forestrie/forestrie-cli`, Forestrie's
  command-line verifier, from npm at an exact version. It is a second
  implementation, not an independent one: both use
  `@forestrie/receipt-verify`. For every tamper variant under both
  signature roots, our `ok`, `stage`, `reason` and `stages[]` must equal the
  reference's byte for byte, and CI runs it on every pull request. See
  [docs/differential-test.md](docs/differential-test.md).
- **Frozen conformance vectors**, sha256-pinned to their manifest, shipped
  inside the tarball. See [fixtures/PROVENANCE.md](fixtures/PROVENANCE.md).
- **`files` includes `src`.** The package that asks you to trust its
  arithmetic ships the arithmetic.
- **Exact, provenance-attested dependencies** — no bundling, so
  `npm ls` and `npm audit signatures` both see the real graph. Bundling would
  hide `@forestrie/receipt-verify`'s own SLSA attestation behind ours.

The verification itself is `@forestrie/receipt-verify`, pinned to an exact
version, published, MIT, and SLSA-attested independently of this package.
`decode_receipt`'s rendering stays a local implementation — over the same
published packages, against the same public
[label registry](https://github.com/forestrie/protocol/blob/main/spec/label-registry.md) —
rather than a dependency on `@forestrie/forestrie-cli`, whose published
decoder is otherwise a drop-in. Delegating to it has been tried twice and
reverted twice: the two label tables still name some codepoints with
different text, and that text is output the tool prints, so adopting it is a
deliberate change to what you see rather than a dependency bump. The
consolation is that it keeps the differential test's decode comparison
meaningful — two separately written renderers that agree, rather than one
compared with itself. See [AGENTS.md](AGENTS.md).

Installing the package pulls in more than a verifier needs.
`@modelcontextprotocol/sdk` brings a web stack, including express, hono,
jose, cors and ajv, for HTTP transports this package never uses: it
constructs only the stdio transport. The verification core never imports
the SDK, and the browser-safety gate enforces that, so importing the
package's `"."` export gives you the arithmetic without any of it.

At release time, this package also registers its own provenance in a
Forestrie log and ships the receipt inside the tarball — two independent
trust roots, npm's SLSA provenance and a Forestrie receipt, rather than one
circular one. See [docs/self-registration.md](docs/self-registration.md).

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

## Licence

MIT.
