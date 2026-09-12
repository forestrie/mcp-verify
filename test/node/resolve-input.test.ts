/**
 * The `node:fs` boundary. Every assertion here exists because the failure it
 * describes would otherwise surface much later, wearing the wrong clothes: a
 * typo'd base64 string that decodes to plausible bytes fails as
 * `receipt_malformed`, which reads as "your receipt is bad" when the truth is
 * "your argument is bad".
 */
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  InputError,
  resolveBytes,
  resolveRoot,
} from "../../src/node/resolve-input.js";
import { readFixture } from "../../src/node/fixtures.js";

const RECEIPT = readFixture("golden/grant-receipt.cbor");
const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");

const dir = mkdtempSync(join(tmpdir(), "mcp-verify-"));
const receiptPath = join(dir, "receipt.cbor");
writeFileSync(receiptPath, RECEIPT);
const emptyPath = join(dir, "empty.cbor");
writeFileSync(emptyPath, new Uint8Array());

describe("resolveBytes", () => {
  it("decodes base64 to the exact bytes", () => {
    expect(resolveBytes({ b64: b64(RECEIPT) })).toEqual(RECEIPT);
  });

  it("reads a path to the exact bytes", () => {
    expect(resolveBytes({ path: receiptPath })).toEqual(RECEIPT);
  });

  it("tolerates surrounding whitespace in base64", () => {
    expect(resolveBytes({ b64: `\n  ${b64(RECEIPT)}  \n` })).toEqual(RECEIPT);
  });

  /**
   * Buffer.from(s, "base64") silently discards anything it does not
   * understand, so this string would otherwise decode to a handful of bytes
   * and fail as a malformed receipt three layers down.
   */
  it("rejects a string that is not base64 at all", () => {
    expect(() => resolveBytes({ b64: "!!!! not base64 !!!!" })).toThrow(
      InputError,
    );
  });

  it("rejects base64 that does not round-trip (truncated group)", () => {
    expect(() => resolveBytes({ b64: "QUJDR" })).toThrow(/round-trip/);
  });

  it("rejects an empty base64 string", () => {
    expect(() => resolveBytes({ b64: "" })).toThrow(InputError);
  });

  it("names the field and the path when a file cannot be read", () => {
    expect(() =>
      resolveBytes({ path: join(dir, "nope.cbor") }, "receipt"),
    ).toThrow(/cannot read receipt.path/);
  });

  it("rejects an empty file rather than verifying zero bytes", () => {
    expect(() => resolveBytes({ path: emptyPath })).toThrow(/0 bytes/);
  });

  it("rejects an empty path string", () => {
    expect(() => resolveBytes({ path: "  " })).toThrow(InputError);
  });
});

describe("resolveRoot", () => {
  it("resolves genesis", () => {
    const r = resolveRoot({ root: "genesis", genesis: { b64: b64(RECEIPT) } });
    expect(r).toEqual({ root: "genesis", genesis: RECEIPT });
  });

  it("resolves known-log-key from a path", () => {
    const r = resolveRoot({
      root: "known-log-key",
      keyXy: { path: receiptPath },
    });
    expect(r).toEqual({ root: "known-log-key", keyXy: RECEIPT });
  });

  /**
   * exactOptionalPropertyTypes is on, so an absent optional must be ABSENT,
   * not present-and-undefined. The core's union narrowing depends on it.
   */
  it("omits absent optionals rather than setting them to undefined", () => {
    const r = resolveRoot({
      root: "known-accumulator",
      accumulator: { b64: b64(RECEIPT) },
    });
    expect(Object.hasOwn(r, "massif")).toBe(false);
    expect(Object.hasOwn(r, "consistencyProof")).toBe(false);
  });

  it("carries present optionals through", () => {
    const r = resolveRoot({
      root: "known-accumulator",
      accumulator: { b64: b64(RECEIPT) },
      massif: { path: receiptPath },
    });
    expect(r).toMatchObject({ root: "known-accumulator", massif: RECEIPT });
  });

  it("resolves a checkpoint chain in order", () => {
    const r = resolveRoot({
      root: "checkpoint-chain",
      checkpoints: [{ path: receiptPath }, { b64: b64(RECEIPT) }],
      keyXy: { b64: b64(RECEIPT) },
    });
    expect(r).toMatchObject({ root: "checkpoint-chain" });
    if (r.root === "checkpoint-chain") expect(r.checkpoints).toHaveLength(2);
  });

  it("refuses an empty checkpoint chain", () => {
    expect(() =>
      resolveRoot({
        root: "checkpoint-chain",
        checkpoints: [],
        keyXy: { b64: b64(RECEIPT) },
      }),
    ).toThrow(/must not be empty/);
  });

  /**
   * Caught here rather than in core, so the message can name the INPUT field
   * the caller has to fix instead of the internal argument core would name.
   */
  it("refuses a checkpoint chain with no trust root, naming the remedy", () => {
    expect(() =>
      resolveRoot({
        root: "checkpoint-chain",
        checkpoints: [{ b64: b64(RECEIPT) }],
      }),
    ).toThrow(/trust.genesis or trust.keyXy/);
  });

  it("names the offending checkpoint index", () => {
    expect(() =>
      resolveRoot({
        root: "checkpoint-chain",
        checkpoints: [{ b64: b64(RECEIPT) }, { path: join(dir, "nope") }],
        keyXy: { b64: b64(RECEIPT) },
      }),
    ).toThrow(/trust.checkpoints\[1\]/);
  });
});
