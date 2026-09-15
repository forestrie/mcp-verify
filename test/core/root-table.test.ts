/**
 * The D3 root table, as a test.
 *
 * plan-2609-02 D3 claims a specific thing about the same bytes at two
 * different roots, and this file is that claim in executable form. Where the
 * runtime disagreed with the table as written, the RUNTIME WON and the
 * divergence is recorded below and in docs/trust-roots.md — a plan is a
 * hypothesis about arithmetic, and the arithmetic is the authority.
 *
 * ## Three places the runtime disagreed with the plan's table
 *
 * 1. **The accumulator root reports `stage=signature`, not `stage=inclusion`.**
 *    `verifyReceiptOfflineAgainstKnownAccumulator` labels a peak mismatch
 *    `{stage: "signature", reason: "peak_not_in_known_accumulator"}` even
 *    though no signature was evaluated. The D3 SEPARATION is real and is
 *    asserted below — it just lives in `reason` and in `questions`, not in
 *    the stage name. Passed through verbatim so `stages[]` keeps the
 *    `forestrie` CLI's contract. Diagnostic:
 *    `accumulator_failure_reported_at_signature_stage`.
 *
 * 2. **A flipped signature byte PASSES at the accumulator root.** The plan's
 *    table said "same" (a signature failure at both roots). It is not: this
 *    root evaluates no signature at all. The recomputed peak comes from leaf
 *    + inclusion path, both untouched by a signature flip, so it still
 *    matches the accumulator — and matching a consistency-gated on-chain
 *    accumulator IS the proof, because univocity refuses to publish a
 *    checkpoint whose signature does not verify. The receipt's own COSE
 *    signature is not what that root trusts. Asserted explicitly below,
 *    because it is the most surprising cell in the table and a future
 *    "fix" that made it fail would be destroying the separation, not
 *    restoring safety.
 *
 * 3. **Truncation and garbage report `receipt_malformed`, not a distinct
 *    reason each.** The plan only claimed `stage=parse` for both, which
 *    holds.
 */
import { describe, expect, it } from "vitest";
import { verifyGrantReceipt } from "../../src/core/index.js";
import type { VerifyResult } from "../../src/core/index.js";
import { GOLDEN_MANIFEST, fromHex } from "../../src/node/fixtures.js";
import { GENESIS, grantCases, type TamperName } from "./tamper.js";
import {
  goldenAccumulatorSnapshot,
  recomputePeak,
  snapshotOverPeaks,
} from "./accumulator.js";

const KEY_XY = fromHex(GOLDEN_MANIFEST.grantDataHex);

/** The snapshot is built ONCE from the clean receipt and held fixed across
 *  every tamper variant — see test/core/accumulator.ts for what that does and
 *  does not prove. */
const SNAPSHOT = await goldenAccumulatorSnapshot(grantCases()[0]!);

type Cell = { ok: boolean; stage: string; reason: string | undefined };

async function run(
  name: TamperName,
  root: "genesis" | "known-log-key" | "known-accumulator",
): Promise<VerifyResult> {
  const c = grantCases().find((x) => x.name === name);
  if (c === undefined) throw new Error(`no tamper case '${name}'`);
  const trust =
    root === "genesis"
      ? ({ root: "genesis", genesis: GENESIS } as const)
      : root === "known-log-key"
        ? ({ root: "known-log-key", keyXy: KEY_XY } as const)
        : ({ root: "known-accumulator", accumulator: SNAPSHOT } as const);
  return verifyGrantReceipt({
    receipt: c.receipt,
    committedGrant: c.committedGrant,
    entryId: c.entryId,
    trust,
  });
}

const cell = (r: VerifyResult): Cell => ({
  ok: r.ok,
  stage: r.stage,
  reason: r.reason,
});

const PASS: Cell = { ok: true, stage: "binding", reason: undefined };
const COLLAPSED: Cell = {
  ok: false,
  stage: "signature",
  reason: "signature_invalid",
};
const PEAK_MISS: Cell = {
  ok: false,
  stage: "signature",
  reason: "peak_not_in_known_accumulator",
};
const MALFORMED: Cell = {
  ok: false,
  stage: "parse",
  reason: "receipt_malformed",
};

describe("D3 — the collapse at genesis and known-log-key", () => {
  /**
   * THE claim. Four structurally different tampers, one indistinguishable
   * answer. A detached-payload receipt's signature covers the MMR peak, which
   * is only knowable after recomputing it from leaf + path — so at a root
   * with no independent accumulator, "the path is wrong", "the committed
   * thing is wrong", "the idtimestamp is wrong" and "the signature is wrong"
   * are the same observation.
   */
  const collapsing: TamperName[] = [
    "signature",
    "inclusion-path",
    "committed-grant",
    "idtimestamp",
  ];

  for (const root of ["genesis", "known-log-key"] as const) {
    for (const name of collapsing) {
      it(`${root}: ${name} collapses to signature/signature_invalid`, async () => {
        expect(cell(await run(name, root))).toEqual(COLLAPSED);
      });
    }

    it(`${root}: the clean receipt passes`, async () => {
      expect(cell(await run("clean", root))).toEqual(PASS);
    });

    it(`${root}: structural corruption is a parse failure, not a signature one`, async () => {
      expect(cell(await run("truncation", root))).toEqual(MALFORMED);
      expect(cell(await run("garbage", root))).toEqual(MALFORMED);
    });

    it(`${root}: split-view is not answered, and a diagnostic says why`, async () => {
      const r = await run("clean", root);
      expect(r.questions["split-view"].status).toBe(
        "not_answered_by_this_root",
      );
      expect(r.diagnostics.map((d) => d.code)).toContain(
        "root_answers_no_split_view",
      );
    });

    it(`${root}: the collapse diagnostic is present — detached payload + no accumulator`, async () => {
      for (const name of ["clean", ...collapsing] as TamperName[]) {
        const r = await run(name, root);
        expect(r.diagnostics.map((d) => d.code)).toContain(
          "detached_payload_stage_collapse",
        );
      }
    });

    it(`${root}: the collapse diagnostic is ABSENT when nothing parsed`, async () => {
      // Nothing was detached because nothing decoded — claiming the collapse
      // here would be describing a receipt that does not exist.
      const r = await run("garbage", root);
      expect(r.diagnostics.map((d) => d.code)).not.toContain(
        "detached_payload_stage_collapse",
      );
    });
  }
});

describe("D3 — the separation at known-accumulator", () => {
  /**
   * The private-branch shape. The receipt is untouched and its signature is
   * genuine, but the accumulator you trust does not hold its peak — which is
   * exactly what a receipt from a state the operator never published looks
   * like. At genesis it PASSES, indistinguishable from an honest receipt,
   * because the root is material the operator controls. Here it is a
   * split-view failure.
   */
  it("an untouched receipt whose peak the trusted accumulator lacks: passes at genesis, split-view fails here", async () => {
    const c = grantCases()[0]!;
    const { leafIndex } = await recomputePeak(c);
    const foreign = snapshotOverPeaks(
      [new Uint8Array(32).fill(0x11)],
      leafIndex + 1n,
    );
    const lower = await run("clean", "genesis");
    expect(cell(lower)).toEqual(PASS);
    expect(lower.questions["split-view"].status).toBe(
      "not_answered_by_this_root",
    );
    const anchored = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: c.committedGrant,
      entryId: c.entryId,
      trust: { root: "known-accumulator", accumulator: foreign },
    });
    expect(cell(anchored)).toEqual(PEAK_MISS);
    expect(anchored.questions["split-view"].status).toBe("failed");
    expect(anchored.anchor?.anchored).toBe(false);
  });

  it("the clean receipt passes and split-view is answered ok", async () => {
    const r = await run("clean", "known-accumulator");
    expect(cell(r)).toEqual(PASS);
    expect(r.questions["split-view"].status).toBe("ok");
    expect(r.anchor?.anchored).toBe(true);
    expect(r.anchor?.matchedPeak).toBe(0);
    expect(r.anchor?.peakCount).toBe(1);
  });

  /**
   * The separation. At genesis these three were indistinguishable from a bad
   * signature; here each is a distinct verdict with `split-view: failed`.
   */
  for (const name of [
    "inclusion-path",
    "committed-grant",
    "idtimestamp",
  ] as TamperName[]) {
    it(`${name} separates: peak_not_in_known_accumulator, split-view failed`, async () => {
      const r = await run(name, "known-accumulator");
      expect(cell(r)).toEqual(PEAK_MISS);
      expect(r.questions["split-view"].status).toBe("failed");
      expect(r.anchor?.anchored).toBe(false);
      expect(r.anchor?.matchedPeak).toBeNull();
      // Runtime divergence 1: the stage label says "signature" although no
      // signature ran. The diagnostic is what stops that misleading a reader.
      expect(r.diagnostics.map((d) => d.code)).toContain(
        "accumulator_failure_reported_at_signature_stage",
      );
    });
  }

  /**
   * Runtime divergence 2, asserted deliberately rather than left as a
   * surprise. This root does not evaluate the receipt's COSE signature; a
   * flipped signature byte leaves the leaf and path — and therefore the
   * recomputed peak — untouched, so the anchor still matches. That is the
   * root's actual trust model, not a hole in it: the authority is the
   * consistency-gated on-chain accumulator, and univocity refuses to publish
   * a checkpoint whose signature does not verify.
   *
   * If this test ever goes red because someone made the accumulator root also
   * re-check the signature, they will have collapsed the roots back together
   * and destroyed the separation the two tests above assert. Read
   * docs/trust-roots.md before "fixing" it.
   */
  it("a flipped signature byte PASSES here — this root checks no signature", async () => {
    const r = await run("signature", "known-accumulator");
    expect(cell(r)).toEqual(PASS);
    expect(r.questions["sealing"].status).toBe("ok");
    expect(r.questions["sealing"].note).toContain("implied by the anchor");
    const signature = r.stages.find((s) => s.stage === "signature");
    expect(signature?.reason).toContain("not re-checked locally");
  });

  it("structural corruption is still a parse failure", async () => {
    expect(cell(await run("truncation", "known-accumulator"))).toEqual(
      MALFORMED,
    );
    expect(cell(await run("garbage", "known-accumulator"))).toEqual(MALFORMED);
  });

  it("no root_answers_no_split_view diagnostic — this root answers it", async () => {
    const r = await run("clean", "known-accumulator");
    expect(r.diagnostics.map((d) => d.code)).not.toContain(
      "root_answers_no_split_view",
    );
    expect(r.diagnostics.map((d) => d.code)).not.toContain(
      "detached_payload_stage_collapse",
    );
  });

  it("a receipt newer than the snapshot fails CLOSED with a refresh remedy", async () => {
    const c = grantCases()[0]!;
    const { snapshotOverPeaks, recomputePeak } =
      await import("./accumulator.js");
    const { peak, leafIndex } = await recomputePeak(c);
    // size == leafIndex means the leaf is NOT covered: staleness limits
    // coverage, never validity, so this must fail rather than pass.
    const stale = snapshotOverPeaks([peak], leafIndex);
    const r = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: c.committedGrant,
      entryId: c.entryId,
      trust: { root: "known-accumulator", accumulator: stale },
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("receipt_newer_than_known_accumulator");
  });
});

describe("the four questions are answered for every root and every variant", () => {
  it("no question is ever missing, and every answer carries a note", async () => {
    for (const root of [
      "genesis",
      "known-log-key",
      "known-accumulator",
    ] as const) {
      for (const c of grantCases()) {
        const r = await run(c.name, root);
        for (const q of [
          "split-view",
          "sealing",
          "append-authority",
          "attribution",
        ] as const) {
          expect(r.questions[q], `${root}/${c.name}/${q}`).toBeDefined();
          expect(r.questions[q].note.length).toBeGreaterThan(10);
        }
        expect(r.root).toBe(root);
        expect(r.verifier.package).toBe("@forestrie/mcp-verify");
      }
    }
  });

  it("append-authority is answered for a grant receipt and never for a payload one", async () => {
    const r = await run("clean", "genesis");
    expect(r.questions["append-authority"].status).toBe("ok");
    expect(r.diagnostics.map((d) => d.code)).not.toContain(
      "grant_authority_not_checked_for_payload_receipt",
    );
  });
});
