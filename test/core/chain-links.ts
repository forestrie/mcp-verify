/**
 * Retained-checkpoint builders for the checkpoint-chain constraint tests,
 * generated at run time (no committed evidence).
 *
 * The chain is over the KS256 fixture's two-leaf MMR (size 3): node 0 is the
 * sibling `0x42…` in the receipt's inclusion path, node 1 is the receipt's
 * leaf (mmrIndex 1), node 2 is the peak. That lets a chain be built in one
 * link (0 -> 3, covers the leaf) or two (0 -> 1, then 1 -> 3), where the
 * first link's signed size 1 does NOT cover the leaf at index 1.
 *
 * Certificates are signed by a fresh ES256 root, with caller-chosen
 * constraint labels (3 mmrStart, 4 mmrEnd, 8 issuedAt, 9 expiresAt) or none.
 */
import { normalizeEs256SignatureLowS } from "@forestrie/delegation-cose";
import {
  COSE_LABEL_TREE_SIZE_2,
  COSE_LABEL_VDP,
  COSE_LABEL_VDS,
  VDP_CONSISTENCY_PROOF_KEY,
  VDS_MMR_CONSISTENCY,
  encodeCborDeterministic,
  encodeSigStructure,
} from "@forestrie/encoding";
import {
  accumulatorPayload,
  univocityLeafHash,
} from "@forestrie/receipt-verify";
import type { Ks256Fixture } from "./ks256-fixture.js";

export type Es256Root = { pair: CryptoKeyPair; keyXy: Uint8Array };

export async function newEs256Root(): Promise<Es256Root> {
  const pair = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const raw = new Uint8Array(
    (await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer,
  );
  return { pair, keyXy: raw.slice(1) };
}

async function es256Sign(
  key: CryptoKey,
  bytes: Uint8Array,
): Promise<Uint8Array> {
  return normalizeEs256SignatureLowS(
    new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        key,
        new Uint8Array(bytes),
      ),
    ),
  );
}

/** Unix seconds of the fixture leaf's snowflake idtimestamp (all 0x02 bytes). */
export function leafUnixSeconds(fx: Ks256Fixture): number {
  const id = new DataView(
    fx.idtimestampBe8.buffer,
    fx.idtimestampBe8.byteOffset,
    8,
  ).getBigUint64(0, false);
  return Number(((1n << 40n) - 1n + (id >> 24n)) / 1000n);
}

export type CertLimits = {
  mmrStart?: bigint;
  mmrEnd?: bigint;
  issuedAt?: number;
  expiresAt?: number;
};

/** A root-signed delegation certificate for the fixture's sealer key. */
export async function buildEs256Cert(
  root: Es256Root,
  fx: Ks256Fixture,
  limits: CertLimits,
): Promise<Uint8Array> {
  const raw = new Uint8Array(
    (await crypto.subtle.exportKey("raw", fx.sealer.publicKey)) as ArrayBuffer,
  );
  const payload = new Map<number, unknown>([
    [
      5,
      new Map<number, unknown>([
        [1, 2],
        [-1, 1],
        [-2, raw.slice(1, 33)],
        [-3, raw.slice(33, 65)],
      ]),
    ],
  ]);
  if (limits.mmrStart !== undefined) payload.set(3, limits.mmrStart);
  if (limits.mmrEnd !== undefined) payload.set(4, limits.mmrEnd);
  if (limits.issuedAt !== undefined) payload.set(8, limits.issuedAt);
  if (limits.expiresAt !== undefined) payload.set(9, limits.expiresAt);
  const protectedBytes = encodeCborDeterministic(
    new Map<number, unknown>([[1, -7]]),
  );
  const payloadBytes = encodeCborDeterministic(payload);
  const sig = await es256Sign(
    root.pair.privateKey,
    encodeSigStructure(protectedBytes, new Uint8Array(0), payloadBytes),
  );
  return encodeCborDeterministic([
    protectedBytes,
    new Map<number, unknown>(),
    payloadBytes,
    sig,
  ]);
}

/** One `.sth`: a consistency proof body, signed by the sealer, cert at 1000. */
export async function buildLink(
  fx: Ks256Fixture,
  cert: Uint8Array,
  size2: bigint,
  proofBody: unknown[],
  accumulator: Uint8Array[],
): Promise<Uint8Array> {
  const protectedBytes = encodeCborDeterministic(
    new Map<number, unknown>([
      [1, -7],
      [COSE_LABEL_VDS, VDS_MMR_CONSISTENCY],
      [COSE_LABEL_TREE_SIZE_2, size2],
    ]),
  );
  const sig = await es256Sign(
    fx.sealer.privateKey,
    encodeSigStructure(
      protectedBytes,
      new Uint8Array(0),
      accumulatorPayload(accumulator),
    ),
  );
  return encodeCborDeterministic([
    protectedBytes,
    new Map<number, unknown>([
      [
        COSE_LABEL_VDP,
        new Map<number, unknown>([
          [VDP_CONSISTENCY_PROOF_KEY, encodeCborDeterministic(proofBody)],
        ]),
      ],
      [1000, cert],
    ]),
    null,
    sig,
  ]);
}

/** One link, 0 -> 3: the signed size 3 covers the leaf at index 1. */
export function coveringLink(fx: Ks256Fixture, cert: Uint8Array) {
  return buildLink(fx, cert, 3n, [0n, 3n, [], [fx.peak]], [fx.peak]);
}

/**
 * Two links, 0 -> 1 then 1 -> 3. Link 0's signed size 1 does not cover the
 * leaf at index 1; link 1's size 3 does. Each link carries its own cert.
 */
export async function twoLinks(
  fx: Ks256Fixture,
  certFirst: Uint8Array,
  certSecond: Uint8Array,
): Promise<Uint8Array[]> {
  const node0 = new Uint8Array(32).fill(0x42);
  const leafHash = await univocityLeafHash(fx.idtimestampBe8, fx.inner);
  return [
    await buildLink(fx, certFirst, 1n, [0n, 1n, [], [node0]], [node0]),
    await buildLink(fx, certSecond, 3n, [1n, 3n, [[leafHash]], []], [fx.peak]),
  ];
}
