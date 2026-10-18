/**
 * KS256 roots and ERC-1271 attestations at the core API. Every receipt,
 * genesis and attestation is generated at run time (test/core/ks256-fixture.ts);
 * nothing here is committed evidence. The forbidden-fetch setup is active, so
 * a pass also proves none of this reached the network.
 */
import { describe, expect, it } from "vitest";
import { grantCommitmentHashFromGrant } from "@forestrie/receipt-verify";
import { decodeGrantPayload } from "@forestrie/encoding";
import {
  verifyGrantReceipt,
  verifyReceipt,
  type TrustRoot,
} from "../../src/core/index.js";
import { goldenCommittedGrant } from "../../src/node/fixtures.js";
import { grantCases } from "./tamper.js";
import { GENESIS } from "./tamper.js";
import {
  buildKs256Checkpoint,
  buildKs256Fixture,
  encodedAttestationFor,
  KS256_CHAIN_ID,
  type Ks256Fixture,
} from "./ks256-fixture.js";

const PAYLOAD = new TextEncoder().encode("a ks256-rooted statement");

async function payloadFixture(
  opts?: Parameters<typeof buildKs256Fixture>[1],
): Promise<Ks256Fixture> {
  const inner = new Uint8Array(await crypto.subtle.digest("SHA-256", PAYLOAD));
  return buildKs256Fixture(inner, opts);
}

function run(
  fx: Ks256Fixture,
  trust: TrustRoot,
  ks256Attestation?: Uint8Array,
) {
  return verifyReceipt({
    receipt: fx.receipt,
    payload: PAYLOAD,
    entryId: fx.entryId,
    trust,
    ...(ks256Attestation !== undefined ? { ks256Attestation } : {}),
  });
}

const known = (fx: Ks256Fixture, withGenesis = false): TrustRoot => ({
  root: "known-log-key",
  ks256Address: fx.rootAddress,
  ...(withGenesis ? { forestGenesis: fx.genesis } : {}),
});

describe("KS256 genesis root", () => {
  it("verifies an EOA-rooted receipt by ecrecover", async () => {
    const fx = await payloadFixture();
    const r = await run(fx, { root: "genesis", genesis: fx.genesis });
    expect(r.ok).toBe(true);
    expect(r.ks256Attestation).toBeUndefined();
  });

  it("names ks256_root_not_recovered for a contract root, with a diagnostic", async () => {
    const fx = await payloadFixture({ contractRoot: true });
    const r = await run(fx, { root: "genesis", genesis: fx.genesis });
    expect(r.ok).toBe(false);
    expect(r.stage).toBe("signature");
    expect(r.reason).toBe("ks256_root_not_recovered");
    expect(r.diagnostics.map((d) => d.code)).toContain("ks256_root_failure");
    expect(r.questions.sealing.status).toBe("failed");
  });

  it("verifies a contract root with a bound attestation and reports the block", async () => {
    const fx = await payloadFixture({ contractRoot: true });
    const r = await run(
      fx,
      { root: "genesis", genesis: fx.genesis },
      encodedAttestationFor(fx),
    );
    expect(r.ok).toBe(true);
    expect(r.ks256Attestation).toEqual({
      chainId: KS256_CHAIN_ID.toString(),
      blockNumber: "1234",
      blockHash: `0x${"0b".repeat(32)}`,
      address: fx.rootAddressHex.toLowerCase(),
    });
    expect(r.diagnostics.map((d) => d.code)).toContain(
      "ks256_attested_guarantee",
    );
  });
});

describe("attestation used versus not consulted", () => {
  it("reports the attested block and guarantee only when the attestation was needed", async () => {
    const fx = await payloadFixture({ contractRoot: true });
    const r = await run(
      fx,
      { root: "genesis", genesis: fx.genesis },
      encodedAttestationFor(fx),
    );
    expect(r.ok).toBe(true);
    expect(r.ks256Attestation?.blockNumber).toBe("1234");
    const codes = r.diagnostics.map((d) => d.code);
    expect(codes).toContain("ks256_attested_guarantee");
    expect(codes).not.toContain("ks256_attestation_not_consulted");
  });

  it.each([
    [
      "genesis",
      (fx: Ks256Fixture): TrustRoot => ({
        root: "genesis",
        genesis: fx.genesis,
      }),
    ],
    ["known-log-key", (fx: Ks256Fixture) => known(fx, true)],
  ])(
    "an EOA root under %s verifies by ecrecover and the attestation is not used",
    async (_n, trust) => {
      const fx = await payloadFixture();
      const r = await run(fx, trust(fx), encodedAttestationFor(fx));
      expect(r.ok).toBe(true);
      expect(r.ks256Attestation).toBeUndefined();
      const codes = r.diagnostics.map((d) => d.code);
      expect(codes).toContain("ks256_attestation_not_consulted");
      expect(codes).not.toContain("ks256_attested_guarantee");
    },
  );
});

describe("KS256 known-log-key (ks256Address)", () => {
  it("verifies an EOA address", async () => {
    const fx = await payloadFixture();
    const r = await run(fx, known(fx));
    expect(r.ok).toBe(true);
    expect(r.root).toBe("known-log-key");
  });

  it("fails a wrong address with a visible ks256 reason", async () => {
    const fx = await payloadFixture();
    const r = await run(fx, {
      root: "known-log-key",
      ks256Address: new Uint8Array(20).fill(0x55),
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("ks256_root_not_recovered");
  });

  it("contract address without attestation is not recovered", async () => {
    const fx = await payloadFixture({ contractRoot: true });
    const r = await run(fx, known(fx));
    expect(r.reason).toBe("ks256_root_not_recovered");
  });

  it("contract address with attestation and forestGenesis passes", async () => {
    const fx = await payloadFixture({ contractRoot: true });
    const r = await run(fx, known(fx, true), encodedAttestationFor(fx));
    expect(r.ok).toBe(true);
    expect(r.ks256Attestation?.blockNumber).toBe("1234");
  });

  it("without forestGenesis the attestation chain is unbound", async () => {
    const fx = await payloadFixture({ contractRoot: true });
    const r = await run(fx, known(fx), encodedAttestationFor(fx));
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("ks256_attestation_chain_unbound");
    expect(r.ks256Attestation).toBeUndefined();
  });

  it.each([
    [
      "address",
      { address: new Uint8Array(20).fill(0x77) },
      "address_mismatch",
    ],
    ["digest", { digest: new Uint8Array(32).fill(0x77) }, "digest_mismatch"],
    [
      "signatureHash",
      { signatureHash: new Uint8Array(32).fill(0x77) },
      "signature_mismatch",
    ],
    ["chainId", { chainId: 1n }, "chain_mismatch"],
    ["magic", { magic: new Uint8Array(4) }, "magic_invalid"],
  ] as const)(
    "rejects an attestation with another %s",
    async (_f, o, tail) => {
      const fx = await payloadFixture({ contractRoot: true });
      const r = await run(fx, known(fx, true), encodedAttestationFor(fx, o));
      expect(r.ok).toBe(false);
      expect(r.reason).toBe(`ks256_attestation_${tail}`);
      expect(r.diagnostics.map((d) => d.code)).toContain("ks256_root_failure");
    },
  );
});

describe("input errors", () => {
  it("rejects an attestation under known-accumulator and checkpoint-chain", async () => {
    const fx = await payloadFixture({ contractRoot: true });
    const att = encodedAttestationFor(fx);
    for (const trust of [
      { root: "known-accumulator", accumulator: new Uint8Array(8) },
      {
        root: "checkpoint-chain",
        checkpoints: [new Uint8Array(8)],
        genesis: fx.genesis,
      },
    ] as TrustRoot[]) {
      const r = await run(fx, trust, att);
      expect(r.ok).toBe(false);
      expect(r.stage).toBe("parse");
      expect(r.reason).toMatch(/ks256Attestation is only usable with/);
    }
  });

  it("rejects malformed attestation bytes", async () => {
    const fx = await payloadFixture({ contractRoot: true });
    const r = await run(fx, known(fx, true), new Uint8Array([1, 2, 3, 4, 5]));
    expect(r.ok).toBe(false);
    expect(r.stage).toBe("parse");
    expect(r.reason).toMatch(/ks256Attestation is not a valid attestation/);
  });

  it("rejects both keyXy and ks256Address, and neither", async () => {
    const fx = await payloadFixture();
    const both = await run(fx, {
      root: "known-log-key",
      keyXy: new Uint8Array(64),
      ks256Address: fx.rootAddress,
    });
    expect(both.stage).toBe("parse");
    expect(both.reason).toMatch(/exactly one of keyXy/);
    const neither = await run(fx, { root: "known-log-key" });
    expect(neither.stage).toBe("parse");
    expect(neither.reason).toMatch(/exactly one of keyXy/);
  });

  it("rejects a ks256Address that is not 20 bytes", async () => {
    const fx = await payloadFixture();
    const r = await run(fx, {
      root: "known-log-key",
      ks256Address: new Uint8Array(19),
    });
    expect(r.stage).toBe("parse");
    expect(r.reason).toMatch(/20-byte/);
  });
});

describe("grant receipts", () => {
  it("verifies a KS256-rooted grant receipt under ks256Address", async () => {
    const committedGrant = goldenCommittedGrant();
    const inner = await grantCommitmentHashFromGrant(
      decodeGrantPayload(committedGrant),
    );
    const fx = await buildKs256Fixture(inner, { contractRoot: true });
    const base = { receipt: fx.receipt, committedGrant, entryId: fx.entryId };
    const without = await verifyGrantReceipt({
      ...base,
      trust: known(fx, true),
    });
    expect(without.reason).toBe("ks256_root_not_recovered");
    const withAtt = await verifyGrantReceipt({
      ...base,
      trust: known(fx, true),
      ks256Attestation: encodedAttestationFor(fx),
    });
    expect(withAtt.ok).toBe(true);
    expect(withAtt.ks256Attestation?.chainId).toBe(KS256_CHAIN_ID.toString());
  });
});

describe("attestation with an ES256 root", () => {
  it("is not consulted, and the note says the root is ES256, not ecrecover", async () => {
    const clean = grantCases().find((c) => c.name === "clean")!;
    const fx = await payloadFixture({ contractRoot: true });
    const r = await verifyGrantReceipt({
      receipt: clean.receipt,
      committedGrant: clean.committedGrant,
      entryId: clean.entryId,
      trust: { root: "genesis", genesis: GENESIS },
      ks256Attestation: encodedAttestationFor(fx),
    });
    expect(r.ok).toBe(true);
    expect(r.ks256Attestation).toBeUndefined();
    const note = r.diagnostics.find(
      (d) => d.code === "ks256_attestation_not_consulted",
    );
    expect(note?.message).toMatch(/root is an ES256 key/);
    expect(note?.message).not.toMatch(/ecrecover/);
  });

  it("keeps the ecrecover wording for a KS256 EOA root", async () => {
    const fx = await payloadFixture();
    const r = await run(
      fx,
      { root: "genesis", genesis: fx.genesis },
      encodedAttestationFor(fx),
    );
    const note = r.diagnostics.find(
      (d) => d.code === "ks256_attestation_not_consulted",
    );
    expect(note?.message).toMatch(/ecrecover/);
  });
});

describe("notes carry the real guarantee", () => {
  it("an attested pass narrows the sealing note to the block and chain", async () => {
    const fx = await payloadFixture({ contractRoot: true });
    const r = await run(fx, known(fx, true), encodedAttestationFor(fx));
    expect(r.questions.sealing.status).toBe("ok");
    expect(r.questions.sealing.note).toMatch(/at block 1234 on chain 84532/);
    expect(r.questions.sealing.note).toMatch(
      /trusting the party that fetched/,
    );
    expect(r.questions.sealing.note).not.toMatch(/verified locally/);
    const d = r.diagnostics.find((x) => x.code === "ks256_attested_guarantee");
    expect(d?.message).toMatch(/forest chain binding .* asserted by you/);
  });

  it("an unattested pass keeps the local-verification sealing note", async () => {
    const fx = await payloadFixture();
    const r = await run(fx, known(fx));
    expect(r.questions.sealing.note).toMatch(/verified locally/);
  });

  it("a KS256 failure carries the KS256 sealing note", async () => {
    const fx = await payloadFixture({ contractRoot: true });
    const r = await run(fx, known(fx));
    expect(r.questions.sealing.status).toBe("failed");
    expect(r.questions.sealing.note).toMatch(
      /KS256 root could not be tied to the receipt's delegation certificate/,
    );
  });

  it("chain_unbound names the remedy for the root in use", async () => {
    const fx = await payloadFixture({ contractRoot: true });
    const kn = await run(fx, known(fx), encodedAttestationFor(fx));
    expect(
      kn.diagnostics.find((d) => d.code === "ks256_root_failure")?.message,
    ).toMatch(/Supply trust\.forestGenesis/);
  });

  it("chain_unbound under the genesis root says the genesis has no chain binding", async () => {
    const fx = await payloadFixture({ contractRoot: true });
    // A genesis with a KS256 bootstrap key but no chain id.
    const { decodeCborDeterministic, encodeCborDeterministic } =
      await import("@forestrie/encoding");
    const m = decodeCborDeterministic(fx.genesis) as Map<number, unknown>;
    m.delete(-68013);
    const r = await run(
      fx,
      { root: "genesis", genesis: encodeCborDeterministic(m) },
      encodedAttestationFor(fx),
    );
    expect(r.reason).toBe("ks256_attestation_chain_unbound");
    const msg = r.diagnostics.find(
      (d) => d.code === "ks256_root_failure",
    )?.message;
    expect(msg).toMatch(/genesis document carries no chain binding/);
    expect(msg).not.toMatch(/Supply trust\.forestGenesis/);
  });

  it("rejects a forestGenesis that has no chain binding as an input error", async () => {
    const fx = await payloadFixture({ contractRoot: true });
    const r = await run(
      fx,
      {
        root: "known-log-key",
        ks256Address: fx.rootAddress,
        forestGenesis: new Uint8Array([1, 2, 3]),
      },
      encodedAttestationFor(fx),
    );
    expect(r.ok).toBe(false);
    expect(r.stage).toBe("parse");
    expect(r.reason).toMatch(
      /forestGenesis is not a forest genesis with a chain binding/,
    );
  });
});

describe("checkpoint-chain under a KS256 genesis root", () => {
  it("an EOA root vouches for the sealer key through a KS256 cert on the checkpoint", async () => {
    const fx = await payloadFixture();
    const r = await run(fx, {
      root: "checkpoint-chain",
      checkpoints: [await buildKs256Checkpoint(fx)],
      genesis: fx.genesis,
    });
    expect(r.ok).toBe(true);
    expect(r.anchor?.anchored).toBe(true);
    expect(r.questions["split-view"].status).toBe("ok");
  });

  it("a contract / non-matching root fails closed with the delegation reason surfaced", async () => {
    const fx = await payloadFixture({ contractRoot: true });
    const r = await run(fx, {
      root: "checkpoint-chain",
      checkpoints: [await buildKs256Checkpoint(fx)],
      genesis: fx.genesis,
    });
    expect(r.ok).toBe(false);
    expect(r.stage).toBe("parse");
    expect(r.reason).toMatch(/checkpoint chain did not verify/);
    expect(r.reason).toMatch(/\[delegation: ks256_root_not_recovered\]/);
  });
});
