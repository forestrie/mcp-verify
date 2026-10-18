/**
 * The checkpoint-chain root enforces each delegation certificate's limits
 * per link, and accepts an ERC-1271 attestation for a KS256 contract root.
 * Everything is generated at run time; the forbidden-fetch setup is active.
 */
import { describe, expect, it } from "vitest";
import { verifyReceipt, type TrustRoot } from "../../src/core/index.js";
import {
  buildEs256Cert,
  coveringLink,
  leafUnixSeconds,
  newEs256Root,
  twoLinks,
  type CertLimits,
} from "./chain-links.js";
import {
  buildKs256Checkpoint,
  buildKs256Fixture,
  encodedAttestationFor,
  type Ks256Fixture,
} from "./ks256-fixture.js";

const PAYLOAD = new TextEncoder().encode("a chain-rooted statement");

async function fixture(
  opts?: Parameters<typeof buildKs256Fixture>[1],
): Promise<Ks256Fixture> {
  const inner = new Uint8Array(await crypto.subtle.digest("SHA-256", PAYLOAD));
  return buildKs256Fixture(inner, opts);
}

function run(fx: Ks256Fixture, trust: TrustRoot, att?: Uint8Array) {
  return verifyReceipt({
    receipt: fx.receipt,
    payload: PAYLOAD,
    entryId: fx.entryId,
    trust,
    ...(att !== undefined ? { ks256Attestation: att } : {}),
  });
}

/** Limits that comfortably contain the fixture's leaf and size-3 link. */
function wide(fx: Ks256Fixture): CertLimits {
  const t = leafUnixSeconds(fx);
  return {
    mmrStart: 0n,
    mmrEnd: 65535n,
    issuedAt: t - 60,
    expiresAt: t + 3600,
  };
}

describe("checkpoint-chain: delegation limits per link", () => {
  it("passes a certificate whose limits contain the link and the leaf", async () => {
    const fx = await fixture();
    const root = await newEs256Root();
    const cert = await buildEs256Cert(root, fx, wide(fx));
    const r = await run(fx, {
      root: "checkpoint-chain",
      checkpoints: [await coveringLink(fx, cert)],
      keyXy: root.keyXy,
    });
    expect(r.ok).toBe(true);
    expect(r.anchor?.anchored).toBe(true);
  });

  it("passes a certificate carrying no limits at all", async () => {
    const fx = await fixture();
    const root = await newEs256Root();
    // Even 'expired' fields would bite if present; absent labels mean no check.
    const cert = await buildEs256Cert(root, fx, {});
    const r = await run(fx, {
      root: "checkpoint-chain",
      checkpoints: [await coveringLink(fx, cert)],
      keyXy: root.keyXy,
    });
    expect(r.ok).toBe(true);
  });

  it("a partial limit set (label 4 only) is treated as no limits, as receipt-verify does", async () => {
    const fx = await fixture();
    const root = await newEs256Root();
    const cert = await buildEs256Cert(root, fx, { mmrEnd: 0n });
    const r = await run(fx, {
      root: "checkpoint-chain",
      checkpoints: [await coveringLink(fx, cert)],
      keyXy: root.keyXy,
    });
    expect(r.ok).toBe(true);
  });

  it("rejects a link whose signed size runs past mmrEnd with delegation_out_of_range", async () => {
    const fx = await fixture();
    const root = await newEs256Root();
    // size 3 -> size-1 = 2 > mmrEnd 1. The leaf (index 1) is within mmrEnd, so
    // the receipt-only check would have passed this.
    const cert = await buildEs256Cert(root, fx, { ...wide(fx), mmrEnd: 1n });
    const r = await run(fx, {
      root: "checkpoint-chain",
      checkpoints: [await coveringLink(fx, cert)],
      keyXy: root.keyXy,
    });
    expect(r.ok).toBe(false);
    expect(r.stage).toBe("parse");
    expect(r.reason).toMatch(/checkpoint chain did not verify/);
    expect(r.reason).toMatch(/\[delegation: delegation_out_of_range\]/);
    expect(r.diagnostics.map((d) => d.code)).toContain(
      "delegation_limit_violation",
    );
  });

  it("the size bound is exact: mmrEnd == size-1 passes", async () => {
    const fx = await fixture();
    const root = await newEs256Root();
    const cert = await buildEs256Cert(root, fx, { ...wide(fx), mmrEnd: 2n });
    const r = await run(fx, {
      root: "checkpoint-chain",
      checkpoints: [await coveringLink(fx, cert)],
      keyXy: root.keyXy,
    });
    expect(r.ok).toBe(true);
  });

  it("rejects a covering link whose cert expired before the leaf was sequenced", async () => {
    const fx = await fixture();
    const root = await newEs256Root();
    const cert = await buildEs256Cert(root, fx, {
      ...wide(fx),
      expiresAt: leafUnixSeconds(fx) - 10,
    });
    const r = await run(fx, {
      root: "checkpoint-chain",
      checkpoints: [await coveringLink(fx, cert)],
      keyXy: root.keyXy,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/\[delegation: delegation_expired\]/);
    expect(r.diagnostics.map((d) => d.code)).toContain(
      "delegation_limit_violation",
    );
  });

  it("a link that does not cover the leaf is not held to the leaf's time", async () => {
    const fx = await fixture();
    const root = await newEs256Root();
    const expired = await buildEs256Cert(root, fx, {
      ...wide(fx),
      expiresAt: leafUnixSeconds(fx) - 10,
    });
    const live = await buildEs256Cert(root, fx, wide(fx));
    // Link 0 (signed size 1, leaf at index 1) carries the expired cert; link 1
    // (size 3) covers the leaf and carries a live one.
    const r = await run(fx, {
      root: "checkpoint-chain",
      checkpoints: await twoLinks(fx, expired, live),
      keyXy: root.keyXy,
    });
    expect(r.ok).toBe(true);
    expect(r.anchor?.linkCount).toBe(2);
  });

  it("the covering link of the same chain still fails when ITS cert is expired", async () => {
    const fx = await fixture();
    const root = await newEs256Root();
    const expired = await buildEs256Cert(root, fx, {
      ...wide(fx),
      expiresAt: leafUnixSeconds(fx) - 10,
    });
    const live = await buildEs256Cert(root, fx, wide(fx));
    const r = await run(fx, {
      root: "checkpoint-chain",
      checkpoints: await twoLinks(fx, live, expired),
      keyXy: root.keyXy,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/link 1\)/);
    expect(r.reason).toMatch(/\[delegation: delegation_expired\]/);
  });

  it("a forged entryId cannot turn an honest chain into a delegation violation", async () => {
    const fx = await fixture();
    const root = await newEs256Root();
    // The cert is live for the REAL leaf time, expired for a far-future one.
    const cert = await buildEs256Cert(root, fx, wide(fx));
    const forged = `${"ff".repeat(8)}0000000000000001`;
    const r = await verifyReceipt({
      receipt: fx.receipt,
      payload: PAYLOAD,
      entryId: forged,
      trust: {
        root: "checkpoint-chain",
        checkpoints: [await coveringLink(fx, cert)],
        keyXy: root.keyXy,
      },
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("peak_not_in_checkpoint_chain");
    expect(r.diagnostics.map((d) => d.code)).not.toContain(
      "delegation_limit_violation",
    );
  });

  it("the expiry failure names the delegation in the sealing answer", async () => {
    const fx = await fixture();
    const root = await newEs256Root();
    const cert = await buildEs256Cert(root, fx, {
      ...wide(fx),
      expiresAt: leafUnixSeconds(fx) - 10,
    });
    const r = await run(fx, {
      root: "checkpoint-chain",
      checkpoints: [await coveringLink(fx, cert)],
      keyXy: root.keyXy,
    });
    expect(r.questions.sealing.status).toBe("failed");
    expect(r.questions.sealing.note).toMatch(
      /delegation failed \(delegation_expired\)/,
    );
  });

  it("the size bound applies to a non-covering link too", async () => {
    const fx = await fixture();
    const root = await newEs256Root();
    const tight = await buildEs256Cert(root, fx, { ...wide(fx), mmrEnd: 0n });
    const live = await buildEs256Cert(root, fx, wide(fx));
    // Link 0 signs size 1: size-1 = 0 <= mmrEnd 0, within bounds.
    const ok = await run(fx, {
      root: "checkpoint-chain",
      checkpoints: await twoLinks(fx, tight, live),
      keyXy: root.keyXy,
    });
    expect(ok.ok).toBe(true);
    // The same tight cert on the size-3 link is out of range.
    const bad = await run(fx, {
      root: "checkpoint-chain",
      checkpoints: await twoLinks(fx, live, tight),
      keyXy: root.keyXy,
    });
    expect(bad.ok).toBe(false);
    expect(bad.reason).toMatch(/\[delegation: delegation_out_of_range\]/);
  });
});

describe("checkpoint-chain: KS256 contract root with an ERC-1271 attestation", () => {
  const chainTrust = async (fx: Ks256Fixture): Promise<TrustRoot> => ({
    root: "checkpoint-chain",
    checkpoints: [await buildKs256Checkpoint(fx)],
    genesis: fx.genesis,
  });

  it("passes with the attestation and reports the narrower attested guarantee", async () => {
    const fx = await fixture({ contractRoot: true });
    const r = await run(fx, await chainTrust(fx), encodedAttestationFor(fx));
    expect(r.ok).toBe(true);
    expect(r.ks256Attestation).toMatchObject({
      chainId: "84532",
      blockNumber: "1234",
    });
    expect(r.questions.sealing.note).toMatch(/attested|attestation/i);
    expect(r.questions.sealing.note).toMatch(/block 1234 on chain 84532/);
    expect(r.diagnostics.map((d) => d.code)).toContain(
      "ks256_attested_guarantee",
    );
  });

  it("fails closed without the attestation", async () => {
    const fx = await fixture({ contractRoot: true });
    const r = await run(fx, await chainTrust(fx));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/\[delegation: ks256_root_not_recovered\]/);
  });

  it("an attestation with no genesis is an input error", async () => {
    const fx = await fixture({ contractRoot: true });
    const root = await newEs256Root();
    const r = await run(
      fx,
      {
        root: "checkpoint-chain",
        checkpoints: [await buildKs256Checkpoint(fx)],
        keyXy: root.keyXy,
      },
      encodedAttestationFor(fx),
    );
    expect(r.ok).toBe(false);
    expect(r.stage).toBe("parse");
    expect(r.reason).toMatch(/needs trust\.genesis for the forest chain/);
  });

  it("an attestation for a different certificate digest fails", async () => {
    const fx = await fixture({ contractRoot: true });
    const r = await run(
      fx,
      await chainTrust(fx),
      encodedAttestationFor(fx, { digest: new Uint8Array(32).fill(7) }),
    );
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/ks256_attestation_digest_mismatch/);
  });

  it("an attestation for another chain fails with the chain mismatch and the KS256 diagnostic", async () => {
    const fx = await fixture({ contractRoot: true });
    const r = await run(
      fx,
      await chainTrust(fx),
      encodedAttestationFor(fx, { chainId: 1n }),
    );
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(
      /\[delegation: ks256_attestation_chain_mismatch\]/,
    );
    expect(r.diagnostics.map((d) => d.code)).toContain("ks256_root_failure");
    expect(r.questions.sealing.status).toBe("failed");
    expect(r.questions.sealing.note).toMatch(
      /delegation failed \(ks256_attestation_chain_mismatch\).*ks256_root_failure/,
    );
  });

  it("a failed contract root under checkpoint-chain raises ks256_root_failure", async () => {
    const fx = await fixture({ contractRoot: true });
    const r = await run(fx, await chainTrust(fx));
    expect(r.ok).toBe(false);
    const d = r.diagnostics.find((x) => x.code === "ks256_root_failure");
    expect(d?.message).toMatch(/^ks256_root_not_recovered:/);
  });

  it("an unneeded attestation is not labelled ecrecover when an ES256 key verified the links", async () => {
    const fx = await fixture();
    const root = await newEs256Root();
    const cert = await buildEs256Cert(root, fx, wide(fx));
    const r = await run(
      fx,
      {
        root: "checkpoint-chain",
        checkpoints: [await coveringLink(fx, cert)],
        keyXy: root.keyXy,
        genesis: fx.genesis,
      },
      encodedAttestationFor(fx),
    );
    expect(r.ok).toBe(true);
    const d = r.diagnostics.find(
      (x) => x.code === "ks256_attestation_not_consulted",
    );
    expect(d?.message).toMatch(/ES256 key/);
    expect(d?.message).not.toMatch(/ecrecover/);
  });

  it("an attestation the EOA root did not need is reported as not consulted", async () => {
    const fx = await fixture();
    const r = await run(fx, await chainTrust(fx), encodedAttestationFor(fx));
    expect(r.ok).toBe(true);
    expect(r.ks256Attestation).toBeUndefined();
    expect(r.diagnostics.map((d) => d.code)).toContain(
      "ks256_attestation_not_consulted",
    );
  });
});
