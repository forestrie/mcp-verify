/**
 * `decodeReceipt` over the frozen golden receipt. Everything on the Forestrie
 * wire is CBOR, and this is the tool that makes it readable — so the shape it
 * produces is a contract for anyone rendering a receipt in a transcript.
 */
import { describe, expect, it } from "vitest";
import { DecodeReceiptError, decodeReceipt } from "../../src/core/index.js";
import { readFixture } from "../../src/node/fixtures.js";

const RECEIPT = readFixture("golden/grant-receipt.cbor");

describe("decodeReceipt — the golden grant receipt", () => {
  const d = decodeReceipt(RECEIPT);

  it("reports the envelope", () => {
    expect(d.byteLength).toBe(RECEIPT.byteLength);
    // The golden receipt is UNTAGGED (initial byte 0x84 = array(4)), not
    // tag-18 wrapped. parseReceipt tolerates both; the decoder records which.
    expect(d.tag).toBeNull();
  });

  it("names the protected header's algorithm", () => {
    expect(d.protected.alg).toEqual({
      value: -7,
      name: "ES256 (ECDSA P-256 + SHA-256)",
    });
    expect(d.protected.entries).toEqual([
      { label: 1, name: "alg", note: null, value: -7 },
    ]);
    expect(d.protected.kid).toBeNull();
    expect(d.protected.cwtClaims).toBeNull();
  });

  it("names the unprotected header's verifiable-proofs label", () => {
    const labels = d.unprotected.entries.map((e) => e.label);
    expect(labels).toContain(396);
    const proofs = d.unprotected.entries.find((e) => e.label === 396);
    expect(proofs?.name).toBe("verifiable proofs");
    expect(proofs?.note).toBe("COSE receipts (draft)");
    expect(d.unprotected.delegation).toBeNull();
    expect(d.unprotected.peakReceipts).toBeNull();
  });

  it("says the payload is detached, and says what that means for the peak", () => {
    expect(d.payload).toEqual({ detached: true });
    expect(d.inclusion.peakHex).toBeNull();
    expect(d.inclusion.peakSource).toBe(
      "derived at verify time (detached payload)",
    );
  });

  it("renders the inclusion proof", () => {
    expect(d.inclusion.mmrIndex).toBe("1");
    expect(d.inclusion.pathLength).toBe(1);
    expect(d.inclusion.path).toHaveLength(1);
    expect(d.inclusion.path[0]).toMatch(/^[0-9a-f]{64}$/);
  });

  it("renders the signature as hex of the right length for ES256", () => {
    expect(d.signature.byteLength).toBe(64);
    expect(d.signature.hex).toMatch(/^[0-9a-f]{128}$/);
  });

  it("is JSON-serialisable — bytes never leak as objects", () => {
    const round = JSON.parse(JSON.stringify(d)) as typeof d;
    expect(round).toEqual(d);
  });
});

describe("decodeReceipt — failures name the stage that rejected the input", () => {
  it("empty input", () => {
    expect(() => decodeReceipt(new Uint8Array())).toThrow(DecodeReceiptError);
    try {
      decodeReceipt(new Uint8Array());
    } catch (err) {
      expect((err as DecodeReceiptError).stage).toBe("input");
    }
  });

  it("garbage", () => {
    expect(() => decodeReceipt(new Uint8Array([1, 2, 3]))).toThrow(
      DecodeReceiptError,
    );
  });

  it("truncation", () => {
    expect(() =>
      decodeReceipt(RECEIPT.slice(0, Math.floor(RECEIPT.length / 2))),
    ).toThrow(DecodeReceiptError);
  });

  /**
   * A checkpoint carries a consistency proof at header 396 key -2, not an
   * inclusion proof at key -1, so `parseReceipt` rejects it. Honest: this is
   * a receipt decoder, and saying so beats rendering half a checkpoint.
   */
  it("a checkpoint is refused at the inclusion-proof stage", () => {
    const sth = readFixture("golden/burial/sth-0000.cbor");
    try {
      decodeReceipt(sth);
      expect.unreachable("expected a checkpoint to be refused");
    } catch (err) {
      expect(err).toBeInstanceOf(DecodeReceiptError);
      expect((err as DecodeReceiptError).stage).toBe("inclusion-proof");
    }
  });
});
