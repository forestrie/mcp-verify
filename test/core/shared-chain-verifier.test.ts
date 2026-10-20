/**
 * What adopting @forestrie/receipt-verify 3.2.0's shared checkpoint-chain
 * verifier changed: `mmrStart` is enforced, several ERC-1271 attestations are
 * accepted and each one accounted for, and the attached-peak bug that the
 * known-accumulator and checkpoint-chain roots inherited is gone.
 * Everything is generated at run time; the forbidden-fetch setup is active.
 */
import { describe, expect, it } from "vitest";
import {
  decodeCborDeterministic,
  encodeCborDeterministic,
} from "@forestrie/encoding";
import {
  verifyReceipt,
  type TrustRoot,
  type VerifyResult,
} from "../../src/core/index.js";
import {
  buildEs256Cert,
  coveringLink,
  leafUnixSeconds,
  newEs256Root,
  twoLinks,
} from "./chain-links.js";
import {
  attestationFor,
  buildContractCert,
  buildKs256Fixture,
  encodedAttestationFor,
  type Ks256Fixture,
} from "./ks256-fixture.js";
import {
  decodeKnownAccumulator,
  encodeKnownAccumulator,
  encodeKs256Attestation,
} from "@forestrie/receipt-verify";
import { LANE_A_MANIFEST, readFixture } from "../../src/node/fixtures.js";
import { snapshotOverPeaks } from "./accumulator.js";

const PAYLOAD = new TextEncoder().encode("a chain-rooted statement");

async function fixture(
  opts?: Parameters<typeof buildKs256Fixture>[1],
): Promise<Ks256Fixture> {
  const inner = new Uint8Array(await crypto.subtle.digest("SHA-256", PAYLOAD));
  return buildKs256Fixture(inner, opts);
}

function run(
  fx: Ks256Fixture,
  trust: TrustRoot,
  atts: { one?: Uint8Array; many?: Uint8Array[] } = {},
  payload: Uint8Array = PAYLOAD,
  receipt: Uint8Array = fx.receipt,
): Promise<VerifyResult> {
  return verifyReceipt({
    receipt,
    payload,
    entryId: fx.entryId,
    trust,
    ...(atts.one !== undefined ? { ks256Attestation: atts.one } : {}),
    ...(atts.many !== undefined ? { ks256Attestations: atts.many } : {}),
  });
}

describe("checkpoint-chain: mmrStart is enforced", () => {
  const limits = (fx: Ks256Fixture, mmrStart: bigint) => {
    const t = leafUnixSeconds(fx);
    return { mmrStart, mmrEnd: 65535n, issuedAt: t - 60, expiresAt: t + 3600 };
  };

  it("rejects a link signed below mmrStart with delegation_out_of_range", async () => {
    const fx = await fixture();
    const root = await newEs256Root();
    // The link signs size 3: size-1 = 2 < mmrStart 3.
    const cert = await buildEs256Cert(root, fx, limits(fx, 3n));
    const r = await run(fx, {
      root: "checkpoint-chain",
      checkpoints: [await coveringLink(fx, cert)],
      keyXy: root.keyXy,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("delegation_out_of_range");
    expect(r.failedLink).toBe(0);
    expect(r.diagnostics.map((d) => d.code)).toContain(
      "delegation_limit_violation",
    );
    expect(
      r.diagnostics.find((d) => d.code === "delegation_limit_violation")
        ?.message,
    ).toMatch(/mmrStart/);
  });

  it("the lower bound is exact: mmrStart == size-1 passes", async () => {
    const fx = await fixture();
    const root = await newEs256Root();
    const cert = await buildEs256Cert(root, fx, limits(fx, 2n));
    const r = await run(fx, {
      root: "checkpoint-chain",
      checkpoints: [await coveringLink(fx, cert)],
      keyXy: root.keyXy,
    });
    expect(r.ok).toBe(true);
  });

  it("applies to a non-covering link too", async () => {
    const fx = await fixture();
    const root = await newEs256Root();
    const live = await buildEs256Cert(root, fx, limits(fx, 0n));
    // Link 0 signs size 1: size-1 = 0 < mmrStart 1.
    const late = await buildEs256Cert(root, fx, limits(fx, 1n));
    const r = await run(fx, {
      root: "checkpoint-chain",
      checkpoints: await twoLinks(fx, late, live),
      keyXy: root.keyXy,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("delegation_out_of_range");
    expect(r.failedLink).toBe(0);
  });
});

describe("checkpoint-chain: several attestations (a Safe that rotated its delegate)", () => {
  /** Two links, each under its own contract-signed certificate. */
  async function rotated() {
    const fx = await fixture({ contractRoot: true });
    const raw = new Uint8Array(
      (await crypto.subtle.exportKey(
        "raw",
        fx.sealer.publicKey,
      )) as ArrayBuffer,
    );
    const a = buildContractCert(fx, raw, 1);
    const b = buildContractCert(fx, raw, 2);
    const trust: TrustRoot = {
      root: "checkpoint-chain",
      checkpoints: await twoLinks(fx, a.cert, b.cert),
      genesis: fx.genesis,
    };
    const att = (c: typeof a) =>
      encodedAttestationFor(fx, {
        digest: c.certDigest,
        signatureHash: c.certSignatureHash,
      });
    return { fx, trust, a, b, attA: att(a), attB: att(b), att };
  }

  it("passes with one attestation per certificate and reports each", async () => {
    const { fx, trust, attA, attB } = await rotated();
    const r = await run(fx, trust, { many: [attA, attB] });
    expect(r.ok).toBe(true);
    expect(r.ks256Attestations?.unused).toEqual([]);
    expect(r.ks256Attestations?.used).toHaveLength(2);
    expect(r.ks256Attestations?.used.map((u) => [u.index, u.links])).toEqual([
      [0, [0]],
      [1, [1]],
    ]);
    expect(r.ks256Attestations?.used[0]).toMatchObject({
      chainId: "84532",
      blockNumber: "1234",
    });
    // The singular report stays: the first attestation that carried the run.
    expect(r.ks256Attestation?.blockNumber).toBe("1234");
    expect(r.diagnostics.map((d) => d.code)).toContain(
      "ks256_attested_guarantee",
    );
    expect(r.diagnostics.map((d) => d.code)).not.toContain(
      "ks256_attestation_not_consulted",
    );
  });

  it("the order of the attestations does not matter", async () => {
    const { fx, trust, attA, attB } = await rotated();
    const r = await run(fx, trust, { many: [attB, attA] });
    expect(r.ok).toBe(true);
    expect(r.ks256Attestations?.used.map((u) => [u.index, u.links])).toEqual([
      [0, [1]],
      [1, [0]],
    ]);
  });

  it("the singular and plural fields combine", async () => {
    const { fx, trust, attA, attB } = await rotated();
    const r = await run(fx, trust, { one: attA, many: [attB] });
    expect(r.ok).toBe(true);
    expect(r.ks256Attestations?.used).toHaveLength(2);
  });

  it("fails closed when one certificate has no attestation", async () => {
    const { fx, trust, attA } = await rotated();
    const r = await run(fx, trust, { many: [attA] });
    expect(r.ok).toBe(false);
    expect(r.failedLink).toBe(1);
    expect(r.reason).toMatch(/^ks256_/);
    expect(r.diagnostics.map((d) => d.code)).toContain("ks256_root_failure");
    // Never silently ignored, even on a failing run.
    expect(r.ks256Attestations?.used.map((u) => u.index)).toEqual([0]);
  });

  it("the singular field alone cannot cover both certificates", async () => {
    const { fx, trust, attB } = await rotated();
    const r = await run(fx, trust, { one: attB });
    expect(r.ok).toBe(false);
    expect(r.failedLink).toBe(0);
  });

  it("reports an attestation that matches no certificate as unused, with the reason", async () => {
    const { fx, trust, attA, attB } = await rotated();
    const stray = encodedAttestationFor(fx, {
      digest: new Uint8Array(32).fill(9),
      signatureHash: new Uint8Array(32).fill(8),
    });
    const r = await run(fx, trust, { many: [attA, stray, attB] });
    expect(r.ok).toBe(true);
    expect(r.ks256Attestations?.used.map((u) => u.index)).toEqual([0, 2]);
    expect(r.ks256Attestations?.unused).toEqual([
      {
        index: 1,
        digest: `0x${"09".repeat(32)}`,
        reason: "no_matching_certificate",
      },
    ]);
    const note = r.diagnostics.find(
      (d) => d.code === "ks256_attestation_not_consulted",
    );
    expect(note?.message).toMatch(/#1/);
    expect(note?.message).toMatch(/never silently ignored/);
    expect(r.questions.sealing.note).toMatch(/block 1234 on chain 84532/);
  });

  it("an attestation for a certificate that verified without it is not_needed", async () => {
    // EOA-rooted chain: ecrecover verifies the certificate by itself.
    const fx = await fixture();
    const r = await run(
      fx,
      {
        root: "checkpoint-chain",
        checkpoints: [
          await (await import("./ks256-fixture.js")).buildKs256Checkpoint(fx),
        ],
        genesis: fx.genesis,
      },
      { many: [encodedAttestationFor(fx)] },
    );
    expect(r.ok).toBe(true);
    expect(r.ks256Attestations?.used).toEqual([]);
    expect(r.ks256Attestations?.unused.map((u) => u.reason)).toEqual([
      "not_needed",
    ]);
    expect(r.ks256Attestation).toBeUndefined();
  });

  it("a duplicate attestation for a certificate is reported unused: duplicate", async () => {
    const { fx, trust, attA, attB } = await rotated();
    const r = await run(fx, trust, { many: [attA, attA, attB] });
    expect(r.ok).toBe(true);
    expect(r.ks256Attestations?.used.map((u) => u.index)).toEqual([0, 2]);
    expect(r.ks256Attestations?.unused).toMatchObject([
      { index: 1, reason: "duplicate" },
    ]);
  });

  it("an attestation tried for a certificate and refused is listed as rejected", async () => {
    const { fx, trust, a } = await rotated();
    const wrongChain = encodedAttestationFor(fx, {
      digest: a.certDigest,
      signatureHash: a.certSignatureHash,
      chainId: 1n,
    });
    const r = await run(fx, trust, { many: [wrongChain] });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("ks256_attestation_chain_mismatch");
    expect(r.ks256Attestations?.rejected).toMatchObject([
      { index: 0, links: [0] },
    ]);
    expect(r.ks256Attestations?.used).toEqual([]);
  });

  it("malformed attestation bytes name the entry", async () => {
    const { fx, trust, attA } = await rotated();
    const r = await run(fx, trust, {
      many: [attA, new Uint8Array([1, 2, 3])],
    });
    expect(r.ok).toBe(false);
    expect(r.stage).toBe("parse");
    expect(r.reason).toMatch(
      /ks256Attestation is not a valid attestation .*entry 1/,
    );
  });
});

describe("genesis root: several attestations", () => {
  const trust = (fx: Ks256Fixture): TrustRoot => ({
    root: "genesis",
    genesis: fx.genesis,
  });

  it("uses the attestation made for the certificate and reports the others", async () => {
    const fx = await fixture({ contractRoot: true });
    const stray = encodeKs256Attestation(
      attestationFor(fx, { digest: new Uint8Array(32).fill(9) }),
    );
    const r = await run(fx, trust(fx), {
      many: [stray, encodedAttestationFor(fx)],
    });
    expect(r.ok).toBe(true);
    expect(r.ks256Attestations?.used.map((u) => u.index)).toEqual([1]);
    expect(r.ks256Attestations?.unused).toMatchObject([
      { index: 0, reason: "no_matching_certificate" },
    ]);
  });

  it("without a matching attestation the contract root fails and every one is reported unused", async () => {
    const fx = await fixture({ contractRoot: true });
    const stray = encodeKs256Attestation(
      attestationFor(fx, { digest: new Uint8Array(32).fill(9) }),
    );
    const r = await run(fx, trust(fx), { many: [stray] });
    expect(r.ok).toBe(false);
    expect(r.ks256Attestations?.unused).toMatchObject([
      { index: 0, reason: "run_failed" },
    ]);
  });
});

describe("the attached-peak fix (receipt-verify 3.2.0)", () => {
  /** The fixture receipt with its real peak ATTACHED as the COSE payload. */
  function withAttachedPeak(fx: Ks256Fixture): Uint8Array {
    const cose = decodeCborDeterministic(fx.receipt) as unknown[];
    cose[2] = fx.peak;
    return encodeCborDeterministic(cose);
  }

  it("known-accumulator: a real anchored peak attached to a receipt for another payload FAILS", async () => {
    const fx = await fixture();
    const attached = withAttachedPeak(fx);
    const trust: TrustRoot = {
      root: "known-accumulator",
      accumulator: snapshotOverPeaks([fx.peak], 3n),
    };
    // Control: the right payload passes with the attached peak.
    expect((await run(fx, trust, {}, PAYLOAD, attached)).ok).toBe(true);
    // The attached peak IS in the accumulator, but this payload's leaf does
    // not recompute to it. receipt-verify 3.1.0 trusted the attached peak
    // and passed this; 3.2.0 checks it against leaf + inclusion path.
    const wrong = new TextEncoder().encode("a different statement");
    const r = await run(fx, trust, {}, wrong, attached);
    expect(r.ok).toBe(false);
    expect(r.anchor?.anchored).toBe(false);
    expect(r.reason).toBeDefined();
  });

  it("checkpoint-chain: the peak is recomputed, never read from the receipt", async () => {
    const fx = await fixture();
    const root = await newEs256Root();
    const t = leafUnixSeconds(fx);
    const cert = await buildEs256Cert(root, fx, {
      mmrStart: 0n,
      mmrEnd: 65535n,
      issuedAt: t - 60,
      expiresAt: t + 3600,
    });
    const trust: TrustRoot = {
      root: "checkpoint-chain",
      checkpoints: [await coveringLink(fx, cert)],
      keyXy: root.keyXy,
    };
    const attached = withAttachedPeak(fx);
    expect((await run(fx, trust, {}, PAYLOAD, attached)).ok).toBe(true);
    const wrong = new TextEncoder().encode("a different statement");
    const r = await run(fx, trust, {}, wrong, attached);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("peak_not_in_checkpoint_chain");
  });
});

describe("known-accumulator over the REAL lane-A bundle", () => {
  const receipt = readFixture("lane-a/receipt.cbor");
  const statement = readFixture("lane-a/statement.cose");
  const accumulator = readFixture("lane-a/accumulator.cbor");
  const entryId = LANE_A_MANIFEST.entryId;

  const verify = (acc: Uint8Array) =>
    verifyReceipt({
      receipt,
      payload: statement,
      entryId,
      trust: { root: "known-accumulator", accumulator: acc },
    });

  it("passes against the accumulator the contract published, at the peak's position", async () => {
    const r = await verify(accumulator);
    expect(r.ok).toBe(true);
    expect(r.anchor).toMatchObject({
      anchored: true,
      anchoredSize: "11",
      peakCount: 3,
      matchedPeak: 1,
    });
  });

  it("fails when the real peak is in the list at the wrong position", async () => {
    const snap = decodeKnownAccumulator(accumulator);
    const peaks = [...snap.accumulator];
    // Swap the real peak (position 1: node 9 of peaks [6, 9, 10]) to the front.
    [peaks[0], peaks[1]] = [peaks[1]!, peaks[0]!];
    const r = await verify(
      encodeKnownAccumulator({ ...snap, accumulator: peaks }),
    );
    expect(r.ok).toBe(false);
    expect(r.anchor?.anchored).toBe(false);
  });
});
