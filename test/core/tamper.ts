/**
 * The six tamper variants, generated in-test and never committed as files.
 * Committed tamper fixtures rot: they encode
 * one byte offset of one build of one encoder, and the day the encoder moves
 * they test nothing while still passing.
 *
 * Each variant answers a different question — "what if the signature is
 * wrong", "what if the proof is wrong", "what if the committed thing is
 * wrong" — and the point is that under a signature root the arithmetic
 * cannot tell those apart.
 */
import {
  goldenCommittedGrant,
  goldenGrant,
  GOLDEN_MANIFEST,
  fromHex,
  readFixture,
} from "../../src/node/fixtures.js";
import { encodeGrantPayloadV0Canonical } from "@forestrie/encoding";
import { parseReceipt } from "@forestrie/receipt-verify";

export type TamperName =
  | "clean"
  | "signature"
  | "inclusion-path"
  | "committed-grant"
  | "idtimestamp"
  | "truncation"
  | "garbage";

export const TAMPER_NAMES: readonly TamperName[] = [
  "clean",
  "signature",
  "inclusion-path",
  "committed-grant",
  "idtimestamp",
  "truncation",
  "garbage",
];

export type GrantCase = {
  name: TamperName;
  receipt: Uint8Array;
  committedGrant: Uint8Array;
  entryId: string;
  /** One line saying what was changed and why it is interesting. */
  what: string;
};

const RECEIPT = readFixture("golden/grant-receipt.cbor");
export const GENESIS = readFixture("golden/grant-genesis.cbor");
const ENTRY_ID = `${GOLDEN_MANIFEST.idtimestampBe8Hex}0000000000000001`;

/**
 * Flip a byte inside the COSE signature.
 *
 * The signature is the last element of the Sign1 array, so the final byte of
 * a canonically-encoded receipt is inside it. That is exactly what canopy's
 * own golden-vectors test flips.
 */
function tamperSignature(receipt: Uint8Array): Uint8Array {
  const out = receipt.slice();
  out[out.length - 1] = (out[out.length - 1] ?? 0) ^ 0xff;
  return out;
}

/**
 * Flip a byte inside the inclusion path (header 396's proof array).
 *
 * Located by parsing the receipt and searching for the proof path's first
 * element, rather than by a hard-coded offset: an offset would silently start
 * flipping a different field the day the encoder changes, and a tamper test
 * that stops tampering is worse than no test.
 */
function tamperInclusionPath(receipt: Uint8Array): Uint8Array {
  const parsed = parseReceipt(receipt);
  const node = parsed.proof.path[0];
  if (node === undefined) {
    throw new Error("golden receipt has an empty inclusion path");
  }
  const at = indexOfBytes(receipt, node);
  if (at < 0) {
    throw new Error("could not locate the inclusion path inside the receipt");
  }
  const out = receipt.slice();
  out[at] = (out[at] ?? 0) ^ 0xff;
  return out;
}

function indexOfBytes(haystack: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

/** Mutate the committed grantData before re-encoding the grant payload. */
function tamperCommittedGrant(): Uint8Array {
  const grant = goldenGrant();
  const data = fromHex(GOLDEN_MANIFEST.grantDataHex);
  data[0] = (data[0] ?? 0) ^ 0xff;
  return encodeGrantPayloadV0Canonical({ ...grant, grantData: data });
}

/** `wrong[7] ^= 0x01` — exactly canopy's golden-vectors.test.ts:78-88. */
function tamperIdtimestamp(entryId: string): string {
  const idt = fromHex(GOLDEN_MANIFEST.idtimestampBe8Hex);
  idt[7] = (idt[7] ?? 0) ^ 0x01;
  const hex = Array.from(idt, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex}${entryId.slice(16)}`;
}

export function grantCases(): GrantCase[] {
  const clean = {
    receipt: RECEIPT,
    committedGrant: goldenCommittedGrant(),
    entryId: ENTRY_ID,
  };
  return [
    { name: "clean", ...clean, what: "the frozen golden vectors, untouched" },
    {
      name: "signature",
      ...clean,
      receipt: tamperSignature(RECEIPT),
      what: "one byte of the COSE signature flipped",
    },
    {
      name: "inclusion-path",
      ...clean,
      receipt: tamperInclusionPath(RECEIPT),
      what: "one byte of the header-396 inclusion path flipped",
    },
    {
      name: "committed-grant",
      ...clean,
      committedGrant: tamperCommittedGrant(),
      what: "the committed grantData altered before re-encoding",
    },
    {
      name: "idtimestamp",
      ...clean,
      entryId: tamperIdtimestamp(ENTRY_ID),
      what: "the entry id's idtimestamp altered (low bit of byte 7)",
    },
    {
      name: "truncation",
      ...clean,
      receipt: RECEIPT.slice(0, Math.floor(RECEIPT.length / 2)),
      what: "the receipt cut in half",
    },
    {
      name: "garbage",
      ...clean,
      receipt: new Uint8Array([1, 2, 3]),
      what: "three bytes that are not a receipt at all",
    },
  ];
}
