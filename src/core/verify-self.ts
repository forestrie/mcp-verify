/**
 * `verify_self` / `verify --self` (plan-2609-02 step 2.4): does THIS
 * package's own release-time self-registration receipt actually vouch for
 * the bytes it ships?
 *
 * The bundle (`fixtures/self/` at release time; `test/fixtures/self-bundle/`
 * frozen for tests — see its PROVENANCE.md) is six files: `provenance.json`
 * (name/version/gitCommit/builtAt), `statement.cose` (a plain COSE Sign1,
 * ES256, whose payload is the exact `provenance.json` bytes, ATTACHED — not
 * detached), `receipt.cbor`, `genesis.cbor`, `log-key.xy.b64` (the
 * publications log owner's raw 64-byte P-256 point) and `entry-id.txt`.
 *
 * Two things this file checks that a plain `verifyReceipt` call would not:
 *
 * 1. The receipt's leaf commits to the SIGNED STATEMENT BYTES
 *    (`statement.cose`), not to the raw `provenance.json` — verified at
 *    capture with the `forestrie` CLI (see the frozen bundle's PROVENANCE.md):
 *    `--payload statement.cose` PASSES, `--payload provenance.json` reports
 *    `signature_invalid` (the familiar detached-payload-shaped collapse,
 *    except here it is the WRONG PAYLOAD, not a detached one). So step (a)
 *    below always verifies against `statementCose`, never `provenanceJson`
 *    directly, and step (b) is what closes the gap: does `statement.cose`'s
 *    own signed payload actually equal the `provenance.json` bytes the
 *    caller is holding?
 * 2. The publications log is a GRANDCHILD of the forest root (root → auth
 *    log → publications log), and neither `forestrie-cli` nor
 *    `@forestrie/receipt-verify` walks a grant chain down to a child log yet.
 *    So `genesis` reports `delegation_invalid` for this receipt today (it
 *    reaches only one hop), and the default root here is `known-log-key`
 *    with the bundle's own `log-key.xy.b64` — see
 *    docs/self-registration.md, "The grant chain: recorded, not walked".
 *    `self_chain_not_walked` names this every time the root is
 *    `known-log-key` or `genesis`, so a reader is never left assuming the
 *    grant chain was checked.
 */
import {
  decodeCoseSign1,
  verifyCoseSign1WithParsedKey,
} from "@forestrie/encoding";
import { bytesEqual } from "./peak.js";
import type { Diagnostic, QuestionAnswer, VerifyResult } from "./result.js";
import type { TrustRoot } from "./root.js";
import { verifyReceipt } from "./verify-receipt.js";
import { importKnownLogKey, VerifyInputError } from "./verify-shared.js";

/** The release-time self-registration bundle, as bytes. Node loads these
 *  from `fixtures/self/` (`src/node/fixtures.ts`); this type has no opinion
 *  about where they came from. */
export type SelfBundle = {
  /** The unsigned provenance document: `{name, version, gitCommit, builtAt}`. */
  provenanceJson: Uint8Array;
  /** A plain COSE Sign1 (ES256), attached payload = `provenanceJson`. */
  statementCose: Uint8Array;
  /** The Forestrie receipt whose leaf commits `statementCose`. */
  receipt: Uint8Array;
  /** The forest's genesis document. Reports `delegation_invalid` for this
   *  receipt today — see the module doc — but still decodable, still
   *  useful for anyone auditing the chain by hand. */
  genesis: Uint8Array;
  /** Raw 64-byte P-256 x‖y: the publications log owner's public point. */
  logKeyXy: Uint8Array;
  /** 32 lowercase hex: idtimestamp_be8 ‖ mmrIndex_be8. */
  entryId: string;
};

/** `provenance.json`, parsed. `null` when the bytes are not that shape —
 *  a tampered `provenance.json` may not even be valid JSON. */
export type SelfProvenance = {
  name: string;
  version: string;
  gitCommit: string;
  builtAt: string;
};

/**
 * D3's result, extended with what `verify_self` alone checks: whether
 * `statement.cose` actually signs the `provenance.json` bytes supplied, and
 * whether that signature holds under the bundled log key. Everything else
 * (`stages`, `questions`, `diagnostics`, `root`) is the same result shape
 * every other tool returns.
 */
export type SelfVerifyResult = VerifyResult & {
  self: {
    /** `null` when `provenanceJson` did not parse as `{name, version,
     *  gitCommit, builtAt}` — a tampered document may not even be JSON. */
    provenance: SelfProvenance | null;
    /** Does `statement.cose`'s ES256 signature verify under `logKeyXy`? */
    statementSignature: "ok" | "failed";
    /** Does `statement.cose`'s signed payload equal `provenanceJson`,
     *  byte-for-byte? */
    payloadMatchesProvenance: boolean;
  };
};

export type VerifySelfOptions = {
  /**
   * Defaults to `{root: "known-log-key", keyXy: bundle.logKeyXy}` — the
   * bundled release key, not `genesis`. See the module doc for why: the
   * publications log is a grandchild of the forest root and nothing walks
   * the grant chain down to it yet. Pass `genesis` to see that reported
   * (`delegation_invalid`), or a caller-supplied `known-accumulator`
   * snapshot to answer split-view as well.
   */
  root?: TrustRoot;
};

function parseProvenance(bytes: Uint8Array): SelfProvenance | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const p = parsed as Record<string, unknown>;
  if (
    typeof p.name === "string" &&
    typeof p.version === "string" &&
    typeof p.gitCommit === "string" &&
    typeof p.builtAt === "string"
  ) {
    return {
      name: p.name,
      version: p.version,
      gitCommit: p.gitCommit,
      builtAt: p.builtAt,
    };
  }
  return null;
}

const SELF_CHAIN_NOTE =
  "the genesis → root grant → auth log → publications log " +
  "chain is recorded in the logs but not walked by this verifier; the key " +
  "in log-key.xy.b64 is trusted as shipped";

/**
 * `attribution` — "who signed this leaf?" — is where (b) lands. The base
 * answer from `verifyReceipt` only says the receipt commits `statementCose`'s
 * exact bytes; it says nothing about who signed THOSE bytes, or whether they
 * are the provenance document the caller thinks they are. Both are folded in
 * here, because a passing attribution for `verify_self` should mean "the log
 * owner's key signed exactly this provenance.json, and the receipt commits
 * that signed statement" — nothing weaker.
 */
function selfAttribution(
  base: QuestionAnswer,
  statementSignature: "ok" | "failed",
  payloadMatchesProvenance: boolean,
): QuestionAnswer {
  if (base.status === "not_answered_by_this_root") return base;
  if (
    base.status === "ok" &&
    statementSignature === "ok" &&
    payloadMatchesProvenance
  ) {
    return {
      status: "ok",
      note:
        "the statement's ES256 signature verifies under log-key.xy.b64 (the " +
        "log owner's key), its signed payload is byte-for-byte this " +
        "provenance.json, and the receipt commits exactly these statement " +
        "bytes at this entry id",
    };
  }
  const problems: string[] = [];
  if (base.status !== "ok") {
    problems.push(
      "the receipt does not commit these statement bytes at this entry id",
    );
  }
  if (statementSignature !== "ok") {
    problems.push(
      "the statement's ES256 signature did not verify under log-key.xy.b64",
    );
  }
  if (!payloadMatchesProvenance) {
    problems.push(
      "the statement's signed payload does not match provenance.json byte-for-byte",
    );
  }
  return { status: "failed", note: problems.join("; ") };
}

export async function verifySelf(
  bundle: SelfBundle,
  opts?: VerifySelfOptions,
): Promise<SelfVerifyResult> {
  const root: TrustRoot = opts?.root ?? {
    root: "known-log-key",
    keyXy: bundle.logKeyXy,
  };

  // (a) The receipt's leaf commits `statementCose`, never `provenanceJson`
  // directly — see the module doc for the frozen-bundle evidence.
  const base = await verifyReceipt({
    receipt: bundle.receipt,
    payload: bundle.statementCose,
    entryId: bundle.entryId,
    trust: root,
  });

  // (b) The statement's own COSE Sign1, decoded independently of the
  // receipt and always checked against the BUNDLE's own `logKeyXy` — this is
  // the attribution channel (the release key this package ships), not the
  // root the caller chose for (a).
  let payloadMatchesProvenance = false;
  let statementSignature: "ok" | "failed" = "failed";
  const decoded = decodeCoseSign1(bundle.statementCose);
  if (decoded !== null) {
    payloadMatchesProvenance = bytesEqual(
      decoded.payloadBstr,
      bundle.provenanceJson,
    );
    try {
      const key = await importKnownLogKey(bundle.logKeyXy);
      statementSignature = (await verifyCoseSign1WithParsedKey(
        bundle.statementCose,
        key,
      ))
        ? "ok"
        : "failed";
    } catch (err) {
      if (!(err instanceof VerifyInputError)) throw err;
      statementSignature = "failed";
    }
  }

  // (c) provenance.json, parsed for display. `null` on a tampered/garbled
  // document — never thrown.
  const provenance = parseProvenance(bundle.provenanceJson);

  const ok =
    base.ok && statementSignature === "ok" && payloadMatchesProvenance;

  // The mechanical stages/(reason) come from (a) unless (b) is what actually
  // failed: a receipt that mechanically PASSES over statement.cose but signs
  // the wrong document, or is signed by the wrong key, must not report `ok`.
  let stage = base.stage;
  let reason = base.reason;
  if (base.ok && !ok) {
    if (!payloadMatchesProvenance) {
      stage = "binding";
      reason = "self_payload_mismatch";
    } else {
      stage = "signature";
      reason = "self_statement_signature_invalid";
    }
  }

  const diagnostics: Diagnostic[] = [...base.diagnostics];
  if (root.root === "known-log-key" || root.root === "genesis") {
    diagnostics.push({
      code: "self_chain_not_walked",
      message: SELF_CHAIN_NOTE,
    });
  }

  const out: SelfVerifyResult = {
    ok,
    root: base.root,
    stage,
    stages: base.stages,
    questions: {
      ...base.questions,
      attribution: selfAttribution(
        base.questions.attribution,
        statementSignature,
        payloadMatchesProvenance,
      ),
    },
    diagnostics,
    verifier: base.verifier,
    self: { provenance, statementSignature, payloadMatchesProvenance },
  };
  if (reason !== undefined) out.reason = reason;
  if (base.anchor !== undefined) out.anchor = base.anchor;
  return out;
}

/**
 * The one-line human summary, in `summarize`'s shape plus what `verify_self`
 * alone adds: the provenance identity and the two statement-level checks.
 * Never a bare "valid" — same rule, same reason.
 */
export function summarizeSelf(result: SelfVerifyResult): string {
  const prov = result.self.provenance;
  const provStr =
    prov !== null
      ? `${prov.name}@${prov.version} (${prov.gitCommit.slice(0, 12)})`
      : "provenance.json did not parse";
  const head = result.ok
    ? "verify-self: PASS"
    : `verify-self: FAILED at ${result.stage}${
        result.reason !== undefined ? ` (${result.reason})` : ""
      }`;
  const answered = (
    ["sealing", "split-view", "append-authority", "attribution"] as const
  ).map((q) => {
    const a = result.questions[q];
    return `${q} ${
      a.status === "not_answered_by_this_root"
        ? "not answered at this root"
        : a.status
    }`;
  });
  return (
    `${head} · root=${result.root} · ${answered.join(", ")} · ` +
    `self=${provStr}, statementSignature=${result.self.statementSignature}, ` +
    `payloadMatchesProvenance=${result.self.payloadMatchesProvenance}`
  );
}
