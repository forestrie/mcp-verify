/**
 * The only test that proves "agrees with the reference exactly".
 *
 * For each tamper variant × root, materialise the inputs into a temp dir, run
 * `forestrie verify-grant --json`, run our `verifyGrantReceipt()` over the
 * same bytes, and compare the four fields the CLI's `VerifyReport` contract
 * names: `ok`, `stage`, `reason`, `stages`. `questions`, `diagnostics` and
 * `verifier` are ours alone and are not compared.
 *
 * ## When a cell disagrees
 *
 * A disagreement is a FINDING, not a test bug. Triage it as one of:
 *
 *   - **our bug** — fix our code;
 *   - **CLI bug** — pin the expectation here with a comment naming the bug,
 *     and file it.
 *
 * The reference CLI is on the same `@forestrie/receipt-verify` (1.0.0) and
 * `@forestrie/encoding` (0.7.0) as this package from `@forestrie/forestrie-cli
 * @0.8.0` onward, so the version-skew triage row this file used to carry is
 * retired.
 *
 * Never silently loosen an assertion. `docs/differential-test.md` carries the
 * full procedure and the current pinned divergences.
 *
 * ## Cases deliberately NOT in the matrix
 *
 * `verify-grant` with neither `--committed-grant` nor `--committed-grant-file`
 * crashes with an uncaught stack trace, even under `--json`
 * (forestrie-cli `src/options/verify.ts`, cited in plan-2609-02 "What changed
 * on contact" 3). Comparing against a stack trace proves nothing; our own
 * clean validation error is asserted in `test/core/verify-grant-receipt.test.ts`
 * instead, and the CLI bug is filed separately.
 */
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { verifyGrantReceipt, decodeReceipt } from "../../src/core/index.js";
import {
  GOLDEN_MANIFEST,
  fromHex,
  readFixture,
} from "../../src/node/fixtures.js";
import { GENESIS, grantCases, type GrantCase } from "../core/tamper.js";
import { FORESTRIE_CLI_VERSION, resolveCliBinary } from "./cli-binary.js";

const KEY_XY = fromHex(GOLDEN_MANIFEST.grantDataHex);
const KEY_XY_B64 = Buffer.from(KEY_XY).toString("base64");

/**
 * Resolved at MODULE scope, not in `beforeAll`: vitest evaluates
 * `describe.skipIf` at collection time, so a hook-resolved binary skips the
 * whole file every time and reports a cheerful green run that checked
 * nothing. Top-level await is the only place this can be decided.
 */
const outcome = await resolveCliBinary();
const run = outcome.run;
const skipReason = outcome.run === null ? outcome.reason : "";

// CI sets FORESTRIE_DIFFERENTIAL=required; a developer offline gets a clean
// skip with a one-line reason rather than a mysterious pass.
if (run === null && process.env["FORESTRIE_DIFFERENTIAL"] === "required") {
  throw new Error(
    `differential test is required in CI but the pinned forestrie CLI could not be resolved: ${skipReason}`,
  );
}
if (run === null) {
  console.warn(`[differential] SKIPPED: ${skipReason}`);
}

const dir = mkdtempSync(join(tmpdir(), "mcp-verify-diff-"));

/** Write one case's bytes to disk; the CLI is file-oriented. */
function materialise(c: GrantCase): {
  genesis: string;
  receipt: string;
  grant: string;
} {
  const genesis = join(dir, `${c.name}-genesis.cbor`);
  const receipt = join(dir, `${c.name}-receipt.cbor`);
  const grant = join(dir, `${c.name}-grant.cbor`);
  writeFileSync(genesis, GENESIS);
  writeFileSync(receipt, c.receipt);
  writeFileSync(grant, c.committedGrant);
  return { genesis, receipt, grant };
}

type Report = {
  ok: boolean;
  stage: string;
  reason?: string;
  stages: { stage: string; status: string; reason?: string }[];
};

function parseReport(stdout: string, context: string): Report {
  try {
    return JSON.parse(stdout) as Report;
  } catch {
    throw new Error(
      `${context}: the reference CLI did not emit JSON on stdout. This is the ` +
        `signature of an uncaught error, not a verification failure.\n${stdout.slice(0, 800)}`,
    );
  }
}

/** The four fields the CLI's contract names — nothing more, nothing less. */
function comparable(r: {
  ok: boolean;
  stage: string;
  reason?: string;
  stages: { stage: string; status: string; reason?: string }[];
}): Report {
  const out: Report = {
    ok: r.ok,
    stage: r.stage,
    stages: r.stages.map((s) => {
      const row: { stage: string; status: string; reason?: string } = {
        stage: s.stage,
        status: s.status,
      };
      if (s.reason !== undefined) row.reason = s.reason;
      return row;
    }),
  };
  if (r.reason !== undefined) out.reason = r.reason;
  return out;
}

/**
 * The known-log-key root rewrites the narration of PASSING rows
 * (`knownKeyStageRows`), and both implementations do it identically — so the
 * reasons compare too. The genesis root leaves passing rows bare.
 */
describe.skipIf(!run)(
  `differential vs forestrie @forestrie/forestrie-cli@${FORESTRIE_CLI_VERSION}`,
  () => {
    it("(guard) the pinned npm version resolved", () => {
      expect(run, skipReason).not.toBeNull();
      // `env` means FORESTRIE_CLI_BIN was set: an explicit local decision to
      // test against something else, and NOT version-pinned. Say so.
      if (outcome.run !== null && outcome.source === "env") {
        console.warn(
          "[differential] using FORESTRIE_CLI_BIN override — not version-pinned",
        );
      }
    });

    for (const c of grantCases()) {
      describe(`${c.name} — ${c.what}`, () => {
        it("genesis root: ok/stage/reason/stages match", async () => {
          const paths = materialise(c);
          const result = run!([
            "verify-grant",
            "--json",
            "--genesis",
            paths.genesis,
            "--receipt",
            paths.receipt,
            "--committed-grant-file",
            paths.grant,
            "--entry-id",
            c.entryId,
          ]);
          const theirs = parseReport(result.stdout, `${c.name}/genesis`);
          const ours = await verifyGrantReceipt({
            receipt: c.receipt,
            committedGrant: c.committedGrant,
            entryId: c.entryId,
            trust: { root: "genesis", genesis: GENESIS },
          });
          expect(comparable(ours)).toEqual(comparable(theirs));
          // Exit code is part of the contract for a demo script.
          expect(result.status).toBe(theirs.ok ? 0 : 1);
        });

        it("known-log-key root: ok/stage/reason/stages match", async () => {
          const paths = materialise(c);
          const result = run!([
            "verify-grant",
            "--json",
            "--known-log-key",
            KEY_XY_B64,
            "--receipt",
            paths.receipt,
            "--committed-grant-file",
            paths.grant,
            "--entry-id",
            c.entryId,
          ]);
          const theirs = parseReport(result.stdout, `${c.name}/known-log-key`);
          const ours = await verifyGrantReceipt({
            receipt: c.receipt,
            committedGrant: c.committedGrant,
            entryId: c.entryId,
            trust: { root: "known-log-key", keyXy: KEY_XY },
          });
          expect(comparable(ours)).toEqual(comparable(theirs));
        });
      });
    }

    /**
     * `decode_receipt` against `forestrie decode-receipt --json`.
     *
     * Our renderer is written fresh over the published packages rather than
     * copied from the CLI (the CLI is unpublished, and forking 667 lines of
     * someone else's source is a worse trade than a reimplementation the
     * differential keeps honest). It was written to a documented subset and
     * turned out to reproduce the reference output EXACTLY for the golden
     * receipt — nested CBOR rendering of header 396 included — so the
     * assertion is a full deep-equal rather than a subset match.
     *
     * If a future receipt shape breaks this, do NOT weaken it to
     * `toMatchObject` without recording what diverged, and why, in
     * docs/differential-test.md. The one KNOWN behavioural difference is
     * deliberate and cannot show up here: we decode the protected header
     * strictly (`decodeCborDeterministic`), so a non-canonical header renders
     * in the CLI and is refused by us.
     */
    describe("decode_receipt vs decode-receipt --json", () => {
      it("reproduces the reference output exactly for the golden receipt", () => {
        const c = grantCases()[0]!;
        const paths = materialise(c);
        const result = run!(["decode-receipt", "--json", paths.receipt]);
        expect(result.status).toBe(0);
        const theirs = JSON.parse(result.stdout) as Record<string, unknown>;
        // Round-trip ours through JSON so the comparison is of the documents
        // a caller actually receives, not of two in-memory object graphs.
        const ours = JSON.parse(JSON.stringify(decodeReceipt(c.receipt)));
        expect(ours).toEqual(theirs);
      });

      it("reproduces the reference output exactly for the burial receipt", () => {
        const burial = readFixture("golden/burial/burial-receipt.cbor");
        const path = join(dir, "burial-receipt.cbor");
        writeFileSync(path, burial);
        const result = run!(["decode-receipt", "--json", path]);
        expect(result.status).toBe(0);
        const theirs = JSON.parse(result.stdout) as Record<string, unknown>;
        const ours = JSON.parse(JSON.stringify(decodeReceipt(burial)));
        expect(ours).toEqual(theirs);
      });

      it("agrees that garbage is not a receipt", () => {
        const bad = join(dir, "garbage.cbor");
        writeFileSync(bad, new Uint8Array([1, 2, 3]));
        const result = run!(["decode-receipt", "--json", bad]);
        expect(result.status).not.toBe(0);
        expect(() => decodeReceipt(new Uint8Array([1, 2, 3]))).toThrow();
      });
    });
  },
);
