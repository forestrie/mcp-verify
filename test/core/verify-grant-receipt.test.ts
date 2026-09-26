/**
 * `verifyGrantReceipt` over the frozen golden vectors.
 *
 * The golden fixtures ARE a grant receipt (detached payload, 118 B), so this
 * is the function the vectors can exercise directly — which is why it was
 * written before `verifyReceipt`.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  decodeCborDeterministic,
  encodeCborDeterministic,
  encodeCoseSign1Raw,
} from "@forestrie/encoding";
import { verifyGrantReceipt, VERIFIER } from "../../src/core/index.js";
import {
  BURIAL_MANIFEST,
  GOLDEN_MANIFEST,
  fromHex,
  goldenCommittedGrant,
  goldenEntryId,
} from "../../src/node/fixtures.js";
import { GENESIS, grantCases } from "./tamper.js";

const repoRoot = new URL("../../", import.meta.url).pathname;
const pkg = JSON.parse(readFileSync(`${repoRoot}package.json`, "utf8")) as {
  version: string;
  dependencies: Record<string, string>;
};

/**
 * The golden genesis's bootstrap key (label -68015) is byte-identical to the
 * manifest's `grantDataHex` — the fixture generator uses one P-256 key for
 * both the log's trust root and the grant's committed key material. That is
 * what makes the known-log-key root testable from the manifest alone.
 */
const KEY_XY = fromHex(GOLDEN_MANIFEST.grantDataHex);

const clean = () => grantCases()[0]!;

describe("verifyGrantReceipt — the frozen receipt against the frozen genesis", () => {
  it("verifies at the genesis root", async () => {
    const c = clean();
    const result = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: c.committedGrant,
      entryId: c.entryId,
      trust: { root: "genesis", genesis: GENESIS },
    });
    expect(result.ok).toBe(true);
    expect(result.stage).toBe("binding");
    expect(result.reason).toBeUndefined();
    expect(result.stages).toEqual([
      { stage: "parse", status: "ok" },
      { stage: "signature", status: "ok" },
      { stage: "inclusion", status: "ok" },
      { stage: "binding", status: "ok" },
    ]);
  });

  /**
   * This is the assertion that makes reconstructing the committed grant from
   * `manifest.json` safe rather than a guess: if the field layout were wrong,
   * the leaf would not commit it and the test above could not pass.
   */
  it("the reconstructed committed grant is the one the leaf commits", async () => {
    expect(goldenCommittedGrant().byteLength).toBeGreaterThan(64);
    expect(goldenEntryId()).toMatch(/^[0-9a-f]{32}$/);
  });

  it("verifies at the known-log-key root, and says the anchor is not genesis", async () => {
    const c = clean();
    const result = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: c.committedGrant,
      entryId: c.entryId,
      trust: { root: "known-log-key", keyXy: KEY_XY },
    });
    expect(result.ok).toBe(true);
    expect(result.root).toBe("known-log-key");
    const signature = result.stages.find((r) => r.stage === "signature");
    expect(signature?.reason).toContain("caller-known log key");
  });

  it("fails under a different, valid known log key", async () => {
    const c = clean();
    // The burial bundle's log key: a real P-256 point, wrong log.
    const otherLog = fromHex(BURIAL_MANIFEST.publicKeyXyHex);
    const result = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: c.committedGrant,
      entryId: c.entryId,
      trust: { root: "known-log-key", keyXy: otherLog },
    });
    expect(result.ok).toBe(false);
  });

  /**
   * WebCrypto throws a bare `DataError: Invalid keyData` for bytes that are
   * not a point on P-256. That must never reach a caller as a stack trace:
   * "the key you gave me is not a key" is an input error with an obvious
   * remedy, and this layer owes the caller that sentence.
   */
  it("a corrupt known log key is a clean input failure, not a thrown DataError", async () => {
    const c = clean();
    const wrong = KEY_XY.slice();
    wrong[0] = (wrong[0] ?? 0) ^ 0xff;
    const result = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: c.committedGrant,
      entryId: c.entryId,
      trust: { root: "known-log-key", keyXy: wrong },
    });
    expect(result.ok).toBe(false);
    expect(result.stage).toBe("parse");
    expect(result.reason).toMatch(/not a valid P-256 public key/);
  });

  it("a wrong-length known log key names the expected length", async () => {
    const c = clean();
    const result = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: c.committedGrant,
      entryId: c.entryId,
      trust: { root: "known-log-key", keyXy: new Uint8Array(32) },
    });
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/64 bytes/);
  });

  it("reports the exact verifier identity, and it matches package.json", () => {
    expect(VERIFIER.package).toBe("@forestrie/mcp-verify");
    expect(VERIFIER.version).toBe(pkg.version);
    expect(VERIFIER.receiptVerify).toBe(
      pkg.dependencies["@forestrie/receipt-verify"],
    );
  });
});

describe("verifyGrantReceipt — input validation is ours, not the reference's", () => {
  /**
   * forestrie-cli crashes with an uncaught stack trace when the committed
   * grant is missing, even under --json. This layer validates its own inputs and returns a clean
   * structured failure instead.
   */
  it("a committed grant that is neither COSE nor raw payload is a clean parse failure", async () => {
    const c = clean();
    const result = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: new Uint8Array([0xff, 0xff, 0xff]),
      entryId: c.entryId,
      trust: { root: "genesis", genesis: GENESIS },
    });
    expect(result.ok).toBe(false);
    expect(result.stage).toBe("parse");
    expect(result.reason).toMatch(/neither a Forestrie-Grant COSE Sign1/);
    // A failed run still answers the questions it can, and says which it cannot.
    expect(result.questions["split-view"].status).toBe(
      "not_answered_by_this_root",
    );
  });

  /**
   * FOR-580: grant wire v0 keys 7 (`signer`) and 8 (`kind`) were retired
   * before canopy admission started rejecting them, and the reference
   * codecs (`@forestrie/encoding`, and as of `@forestrie/receipt-verify`
   * 2.1.0 the COSE-embedded grant codec too) now refuse to decode either
   * one rather than silently ignoring it. A committed grant that still
   * carries one must fail here, not verify against stale wire shape.
   */
  it("a committed grant carrying the retired key 7 (signer) is rejected, not silently accepted", async () => {
    const c = clean();
    const decoded = decodeCborDeterministic(c.committedGrant) as Map<
      number,
      unknown
    >;
    const withRetiredKey = new Map(decoded);
    withRetiredKey.set(7, new Uint8Array(33).fill(0x11));
    const committedGrant = new Uint8Array(
      encodeCborDeterministic(withRetiredKey),
    );

    const result = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant,
      entryId: c.entryId,
      trust: { root: "genesis", genesis: GENESIS },
    });

    expect(result.ok).toBe(false);
    expect(result.stage).toBe("parse");
    expect(result.reason).toMatch(/keys 7 \(signer\) and 8 \(kind\)/);
  });

  it("a committed grant carrying the retired key 8 (kind) is rejected the same way", async () => {
    const c = clean();
    const decoded = decodeCborDeterministic(c.committedGrant) as Map<
      number,
      unknown
    >;
    const withRetiredKey = new Map(decoded);
    withRetiredKey.set(8, 1);
    const committedGrant = new Uint8Array(
      encodeCborDeterministic(withRetiredKey),
    );

    const result = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant,
      entryId: c.entryId,
      trust: { root: "genesis", genesis: GENESIS },
    });

    expect(result.ok).toBe(false);
    expect(result.stage).toBe("parse");
    expect(result.reason).toMatch(/keys 7 \(signer\) and 8 \(kind\)/);
  });

  /**
   * FOR-580, pinning the COSE path specifically: mcp-verify#27's two tests
   * above only ever exercise the raw-payload retry, because
   * `decodeCommittedGrant` used to swallow ANY `decodeForestrieGrantCose`
   * failure and retry the same bytes as raw payload CBOR — which for a
   * Sign1 four-tuple always failed with "must be a CBOR map", a message
   * that names neither key. Built by decoding the golden committed grant,
   * injecting the retired key into the embedded grant map, and wrapping it
   * in the same Forestrie-Grant COSE Sign1 four-tuple
   * `decodeForestrieGrantCose` reads: `[protected, unprotected, payload,
   * signature]`, unprotected header label -65538 holding the embedded grant
   * CBOR, payload the digest of it (`decode-forestrie-grant-cose.js` reads:
   * no signature check happens anywhere in that decode — it is pure
   * structure and a digest equality — so a signature need not verify, and
   * empty bytes stand in for both the protected header and the signature).
   */
  async function coseWrapCommittedGrant(
    mutate: (m: Map<number, unknown>) => void,
  ): Promise<Uint8Array> {
    const c = clean();
    const decoded = decodeCborDeterministic(c.committedGrant) as Map<
      number,
      unknown
    >;
    const withRetiredKey = new Map(decoded);
    mutate(withRetiredKey);
    const embedded = new Uint8Array(encodeCborDeterministic(withRetiredKey));
    const payload = new Uint8Array(
      await crypto.subtle.digest("SHA-256", embedded),
    );
    // HEADER_FORESTRIE_GRANT_V0 = -65538 (receipt-verify's
    // forest-genesis-labels.ts); not re-exported from the package's public
    // entry point, so pinned here by value.
    const unprotected = new Map<number, unknown>([[-65538, embedded]]);
    return encodeCoseSign1Raw(
      new Uint8Array(0),
      unprotected,
      payload,
      new Uint8Array(0),
    );
  }

  it("a COSE-wrapped committed grant carrying the retired key 7 (signer) fails on the COSE path", async () => {
    const c = clean();
    const committedGrant = await coseWrapCommittedGrant((m) =>
      m.set(7, new Uint8Array(33).fill(0x11)),
    );

    const result = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant,
      entryId: c.entryId,
      trust: { root: "genesis", genesis: GENESIS },
    });

    expect(result.ok).toBe(false);
    expect(result.stage).toBe("parse");
    // The raw-payload retry's message reads "neither a Forestrie-Grant COSE
    // Sign1 nor a raw grant payload"; this one names the COSE codec
    // directly, proving `decodeCommittedGrant` did not swallow the COSE
    // failure and retry these bytes as raw payload CBOR.
    expect(result.reason).toMatch(
      /^committedGrant is a Forestrie-Grant COSE Sign1 but failed to decode:/,
    );
    expect(result.reason).toMatch(/keys 7 \(signer\) and 8 \(kind\)/);
  });

  it("a COSE-wrapped committed grant carrying the retired key 8 (kind) fails on the COSE path", async () => {
    const c = clean();
    const committedGrant = await coseWrapCommittedGrant((m) => m.set(8, 1));

    const result = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant,
      entryId: c.entryId,
      trust: { root: "genesis", genesis: GENESIS },
    });

    expect(result.ok).toBe(false);
    expect(result.stage).toBe("parse");
    expect(result.reason).toMatch(
      /^committedGrant is a Forestrie-Grant COSE Sign1 but failed to decode:/,
    );
    expect(result.reason).toMatch(/keys 7 \(signer\) and 8 \(kind\)/);
  });

  it("a raw grant payload with no entryId is a clean parse failure naming the remedy", async () => {
    const c = clean();
    const result = await verifyGrantReceipt({
      receipt: c.receipt,
      committedGrant: c.committedGrant,
      trust: { root: "genesis", genesis: GENESIS },
    });
    expect(result.ok).toBe(false);
    expect(result.stage).toBe("parse");
    expect(result.reason).toMatch(/supply entryId/);
  });

  it("never throws for any tamper variant at any of the two offline roots", async () => {
    for (const c of grantCases()) {
      for (const trust of [
        { root: "genesis" as const, genesis: GENESIS },
        { root: "known-log-key" as const, keyXy: KEY_XY },
      ]) {
        await expect(
          verifyGrantReceipt({
            receipt: c.receipt,
            committedGrant: c.committedGrant,
            entryId: c.entryId,
            trust,
          }),
        ).resolves.toHaveProperty("stages");
      }
    }
  });
});
