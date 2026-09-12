/**
 * D2: the trust rung is an INPUT UNION, mirroring the reference CLI's flag
 * presence (`forestrie-cli/src/options/verify.ts` documents the same four as
 * a "trust ladder"; the roots are not ordered by strength, and the field name
 * `rung` is kept only for compatibility with it). You
 * do not ask for "verification"; you say which anchor you are willing to
 * trust, and the answer tells you which questions that anchor can answer.
 *
 * The `rpc` rung — the only one that touches the network — is excluded from
 * this package by construction, not by configuration. There is no branch for
 * it here and no code path that could reach one, which is what the
 * browser-safety gate proves independently.
 */

export type TrustRung =
  | {
      /**
       * The log's own genesis document. Self-contained: the trust root is
       * derived from bytes the caller already holds.
       */
      rung: "genesis";
      genesis: Uint8Array;
    }
  | {
      /**
       * A log owner key the caller obtained out of band. Standard SCITT
       * relying-party posture. The "key K owns log L" binding is ASSERTED by
       * the caller's key provenance, not proven.
       */
      rung: "known-log-key";
      /** Raw 64-byte P-256 x‖y. */
      keyXy: Uint8Array;
    }
  | {
      /**
       * A cached, auditable chain read of the log's on-chain accumulator.
       * This rung is the only one that answers split-view, and it answers it
       * WITHOUT a signature check: an anchored peak match implies the
       * publishing signature was valid, because univocity refuses to publish
       * a checkpoint whose signature does not verify.
       */
      rung: "known-accumulator";
      /** `encodeKnownAccumulator` bytes. */
      accumulator: Uint8Array;
      /** Local massif blob for stale-snapshot proof-path extension. */
      massif?: Uint8Array;
      /** Portable top-up artifact for tile-free extension. */
      consistencyProof?: Uint8Array;
    }
  | {
      /**
       * A retained `.sth` chain, folded from a boundary base. Each link's
       * accumulator is computed from the previous one and its signature
       * verified over exactly that computed payload, so the chain carries its
       * own authority once the first link is rooted in `genesis` or `keyXy`.
       */
      rung: "checkpoint-chain";
      checkpoints: readonly Uint8Array[];
      genesis?: Uint8Array;
      keyXy?: Uint8Array;
    };

export type RungName = TrustRung["rung"];

export const RUNG_NAMES = [
  "genesis",
  "known-log-key",
  "known-accumulator",
  "checkpoint-chain",
] as const satisfies readonly RungName[];

/**
 * The rungs that carry an independent accumulator, and therefore the rungs at
 * which split-view is answerable at all. This single predicate is the D3
 * table's load-bearing distinction; `questions.ts` and `verify-*.ts` both read
 * it rather than re-deriving it.
 */
export function rungAnswersSplitView(rung: RungName): boolean {
  return rung === "known-accumulator" || rung === "checkpoint-chain";
}

export function isTrustRung(value: unknown): value is TrustRung {
  if (typeof value !== "object" || value === null) return false;
  const rung = (value as { rung?: unknown }).rung;
  return (
    typeof rung === "string" &&
    (RUNG_NAMES as readonly string[]).includes(rung)
  );
}
