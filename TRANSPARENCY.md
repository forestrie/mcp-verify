# Transparency, receipts, and agents

Background for [@forestrie/mcp-verify](README.md): what a transparency log
adds to an agent's reasoning, where it stops, and what a Forestrie receipt is.

## What is transparency

A signature tells you who said something and that the bytes are unchanged.
It does not tell you whether they said the same thing to anyone else, when
they said it relative to anything else, or whether they later withdrew it.
That is fine while the source's interests align with yours. It stops being
fine when the source is also the party accountable for the claim: a
certificate authority issuing for a domain it should not, a vendor shipping a
build that differs from the one it audited, a counterparty whose record of
the deal is the only record.

Agents meet this constantly. An agent acts on statements it did not witness
being made: a quote, a policy, an approval, a tool result, another agent's
output. When one agent's output is the next agent's input, and the record of
what was said is kept by the party that said it, nobody downstream can go
back and ask "did you really say that, and did you say it to everyone?" An
orchestrator that reports a sub-agent's approval, an agent that installs a
package on the strength of an attestation, an agent that pays on the strength
of a price: each is trusting the source to be its own auditor.

A transparency log changes the shape of the claim. A signed message gives you
the **integrity of one statement**: these bytes, from this key. A log gives
you a **verifiable series**: this statement was appended at a definite
position to a record that can be shown to have only ever grown, so it cannot
be denied or quietly revised afterwards. Transparency is detection, not
prevention. Lies can be logged too; what the log removes is the ability to
rewrite them once someone has looked.

There is one more step. If you trust the source to keep the record, you are
trusting it to show the same record to everyone else. A log that shows you
one history and an auditor another passes every signature check in both
views. Certificate Transparency's own specification names this: a log "that
shows different, inconsistent views of itself to different clients" defeats
auditing, and until that is addressed a log must be treated as a trusted
third party
([RFC 9162 §1](https://www.rfc-editor.org/rfc/rfc9162.html#section-1), §11.3).
This is the **split view**, and it is why a verifier needs something the
operator does not control to compare against. For a Forestrie log that
something is a checkpoint published to an on-chain contract. The next section
says what a receipt is; [docs/trust-roots.md](docs/trust-roots.md) says what
it lets you check, and against which root.

Further reading:

- Certificate Transparency: the original deployment, and
  [how CT works](https://certificate.transparency.dev/howctworks/).
- [transparency.dev](https://transparency.dev/): general-purpose verifiable
  logs, with an explainer on
  [verifiable data structures](https://transparency.dev/verifiable-data-structures/)
  and on why a log is a
  [verifiable transport layer](https://transparency.dev/articles/logs-a-verifiable-transport-layer/)
  rather than a guarantee of truth.
- C2PA's
  [Content Credentials explainer](https://spec.c2pa.org/specifications/specifications/2.4/explainer/Explainer.html):
  provenance for media, including content produced or edited by AI.
- SCITT, the IETF
  [Supply Chain Integrity, Transparency and Trust](https://datatracker.ietf.org/wg/scitt/about/)
  working group, with an introduction at [scitt.io](https://scitt.io/).
  Forestrie is a SCITT transparency service.

## What is a receipt

A Forestrie log is a transparency log in the sense of
[SCITT](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/),
built on a Merkle Mountain Range (MMR). A **receipt** is the proof that one
entry sits inside that log's sealed state. It is a COSE_Sign1 in the shape of
[COSE Receipts](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/),
profiled for MMRs by
[draft-bryce-cose-receipts-mmr-profile](https://datatracker.ietf.org/doc/draft-bryce-cose-receipts-mmr-profile/):

- Protected header `395` names the verifiable data structure: the MMR profile.
- Unprotected header `396` carries the **inclusion proof**: the entry's
  `mmrIndex` and the sibling path from its **leaf** to an MMR **peak**.
- The payload is normally **detached** (COSE payload `null`), so the log
  operator's signature is over the peak, which the verifier recomputes from
  leaf and path.

The leaf commits `SHA-256(idtimestamp ‖ SHA-256(payload))`. The
**idtimestamp** is the sequencer-assigned entry id, and the **payload** is
the exact bytes that were registered. For a **grant receipt** the inner hash
is instead the grant commitment, computed over the fields of the **committed
grant**: the object that admits a signer to the log. The set of peaks at a
given log size is the **accumulator**, and the log operator's signed
commitment to an accumulator is a **checkpoint** (`.sth`), published to
**univocity**, the on-chain contract that gates publication on consistency.

Verifying a receipt therefore has two halves. The arithmetic: parse the COSE,
rebuild the leaf from your copy of the payload and entry id, and walk the
path to a peak. Then the trust: relate that peak to a **trust root you
choose**, either by checking the log operator's signature over it or by
matching it against an accumulator you already trust.
[docs/trust-roots.md](docs/trust-roots.md) lists the four this package
accepts and says when each is the effective choice.

This package does the arithmetic, the trust step, and the decoding, and
nothing else. It does not obtain receipts: those come from the log that
sequenced the entry (`forestrie register` in the
[`forestrie` CLI](https://github.com/forestrie/forestrie-cli) downloads one
after registering), and you keep them alongside the payload. The arithmetic is
[`@forestrie/receipt-verify`](https://github.com/forestrie/canopy/tree/main/packages/libs/receipt-verify),
published independently of this package.

Verification is pure over bytes, so this runs entirely in the caller's
process. An agent that installs it and verifies a receipt has performed the
demonstration **without contacting Forestrie at all**. That is the point.
The README's [Not a trust circle](README.md#not-a-trust-circle) section is
about making it checkable rather than asking you to take it on faith.
