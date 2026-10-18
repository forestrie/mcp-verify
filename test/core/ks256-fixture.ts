/**
 * A KS256-rooted receipt, generated at RUN TIME — nothing here is committed
 * evidence. Keys and signatures are fresh per call.
 *
 * Shape (the same as a real KS256 forest): a P-256 "sealing" key signs the
 * detached MMR peak; a secp256k1 root signs the label-1000 delegation
 * certificate with protected alg -65799 over keccak256(Sig_structure). The
 * root is a 20-byte address in the forest genesis (and in `rootAddress`).
 * A contract root is modelled the way a Safe looks offline: an address with
 * no key, whose certificate signature does not ecrecover to it.
 *
 * Ported from canopy's receipt-verify
 * `test/helpers/ks256-delegated-receipt-fixture.ts`, with the peak taken
 * from this package's own `recomputeReceiptPeak` instead of a hasher.
 */
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  assembleDelegationCertificate,
  buildDelegationToBeSignedKs256,
  normalizeEs256SignatureLowS,
} from "@forestrie/delegation-cose";
import {
  encodeCborDeterministic,
  encodeSigStructure,
  toPaddedWire32,
  uuidToBytes,
} from "@forestrie/encoding";
import {
  ERC1271_MAGIC_VALUE,
  encodeKs256Attestation,
  type Ks256Attestation,
} from "@forestrie/receipt-verify";
import { recomputeReceiptPeak } from "../../src/core/index.js";

/** The chain the fixture's genesis binds (Base Sepolia). */
export const KS256_CHAIN_ID = 84532n;

const LOG_ID = "770e8400-e29b-41d4-a716-446655440002";
const LOG_ID_HEX32 = "770e8400e29b41d4a716446655440002";
const IDTIMESTAMP_BE8 = new Uint8Array(8).fill(0x02);
const ENTRY_ID = `${"02".repeat(8)}0000000000000001`;

function newKs256Root(): { sk: Uint8Array; address: Uint8Array } {
  const sk = secp256k1.utils.randomPrivateKey();
  const pub = secp256k1.getPublicKey(sk, false);
  return { sk, address: keccak_256(pub.slice(1)).slice(-20) };
}

/** `r‖s‖v` secp256k1 signature over keccak256(bytes). */
function ks256Sign(sk: Uint8Array, bytes: Uint8Array): Uint8Array {
  const sig = secp256k1.sign(keccak_256(bytes), sk, { lowS: true });
  const out = new Uint8Array(65);
  out.set(sig.toCompactRawBytes(), 0);
  out[64] = sig.recovery ?? 0;
  return out;
}

/** Snowflake idtimestamp → Unix seconds (mirrors the sealer's scheme). */
function idtimestampToUnixSeconds(be8: Uint8Array): number {
  const id = new DataView(be8.buffer, be8.byteOffset, 8).getBigUint64(
    0,
    false,
  );
  return Number(((1n << 40n) - 1n + (id >> 24n)) / 1000n);
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export type Ks256Fixture = {
  receipt: Uint8Array;
  /** Forest genesis with the root address as bootstrap key and a chain id. */
  genesis: Uint8Array;
  rootAddress: Uint8Array;
  /** `0x` + 40 hex, for the `ks256Address` input. */
  rootAddressHex: string;
  entryId: string;
  idtimestampBe8: Uint8Array;
  /** keccak256(Sig_structure) of the certificate. */
  certDigest: Uint8Array;
  /** keccak256 of the certificate signature. */
  certSignatureHash: Uint8Array;
  /** The receipt's leaf inner hash, as the caller passed it in. */
  inner: Uint8Array;
};

/**
 * @param inner - the leaf's inner ContentHash: SHA-256(payload) for a payload
 *   receipt, the grant commitment hash for a grant receipt.
 */
export async function buildKs256Fixture(
  inner: Uint8Array,
  opts?: { contractRoot?: boolean; wrongSigner?: boolean },
): Promise<Ks256Fixture> {
  const eoa = newKs256Root();
  const rootAddress = opts?.contractRoot
    ? crypto.getRandomValues(new Uint8Array(20))
    : eoa.address;
  const signer =
    opts?.contractRoot || opts?.wrongSigner ? newKs256Root() : eoa;

  const sealer = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const raw = new Uint8Array(
    (await crypto.subtle.exportKey("raw", sealer.publicKey)) as ArrayBuffer,
  );

  const leafTime = idtimestampToUnixSeconds(IDTIMESTAMP_BE8);
  const tbs = buildDelegationToBeSignedKs256(
    {
      logIdHex32: LOG_ID_HEX32,
      mmrStart: 0,
      mmrEnd: 65535,
      delegatedPublicKeyCbor: encodeCborDeterministic(
        new Map<number, unknown>([
          [1, 2],
          [-1, 1],
          [-2, raw.slice(1, 33)],
          [-3, raw.slice(33, 65)],
        ]),
      ),
      issuedAt: leafTime - 3600,
      expiresAt: leafTime + 3600,
      delegationId: new Uint8Array(16),
    },
    rootAddress,
  );
  const certSignature = ks256Sign(signer.sk, tbs.sigStructureBytes);
  const cert = assembleDelegationCertificate(tbs, certSignature);

  const protectedBytes = encodeCborDeterministic(
    new Map<number, unknown>([[1, -7]]),
  );
  const build = (sig: Uint8Array) =>
    encodeCborDeterministic([
      protectedBytes,
      new Map<number, unknown>([
        [
          396,
          new Map<number, unknown>([
            [
              -1,
              [
                new Map<number, unknown>([
                  [1, 1n],
                  [2, [new Uint8Array(32).fill(0x42)]],
                ]),
              ],
            ],
          ]),
        ],
        [1000, cert],
      ]),
      null,
      sig,
    ]);
  // The signature covers the peak, which is only knowable once the receipt
  // (leaf + path) exists: build with a placeholder, recompute, then sign.
  const { peak } = await recomputeReceiptPeak({
    receiptCbor: build(new Uint8Array(64)),
    idtimestampBe8: IDTIMESTAMP_BE8,
    inner,
  });
  const sigStructure = encodeSigStructure(
    protectedBytes,
    new Uint8Array(0),
    peak,
  );
  const es256 = normalizeEs256SignatureLowS(
    new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        sealer.privateKey,
        new Uint8Array(sigStructure),
      ),
    ),
  );

  const genesis = encodeCborDeterministic(
    new Map<number, unknown>([
      [-68009, 2],
      [-68010, toPaddedWire32(uuidToBytes(LOG_ID))],
      [-68011, new Uint8Array(20).fill(0xab)],
      [-68013, KS256_CHAIN_ID.toString()],
      [-68014, -65799],
      [-68015, rootAddress],
    ]),
  );

  return {
    receipt: build(es256),
    genesis,
    rootAddress,
    rootAddressHex: `0x${hex(rootAddress)}`,
    entryId: ENTRY_ID,
    idtimestampBe8: IDTIMESTAMP_BE8,
    certDigest: keccak_256(tbs.sigStructureBytes),
    certSignatureHash: keccak_256(certSignature),
    inner,
  };
}

/** A well-formed attestation for the fixture, with optional overrides. */
export function attestationFor(
  fx: Ks256Fixture,
  overrides: Partial<Ks256Attestation> = {},
): Ks256Attestation {
  return {
    version: 1,
    chainId: KS256_CHAIN_ID,
    address: fx.rootAddress,
    digest: fx.certDigest,
    signatureHash: fx.certSignatureHash,
    blockNumber: 1234n,
    blockHash: new Uint8Array(32).fill(0x0b),
    magic: ERC1271_MAGIC_VALUE,
    ...overrides,
  };
}

export function encodedAttestationFor(
  fx: Ks256Fixture,
  overrides: Partial<Ks256Attestation> = {},
): Uint8Array {
  return encodeKs256Attestation(attestationFor(fx, overrides));
}
