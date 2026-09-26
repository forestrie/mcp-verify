/**
 * Grant receipt verification, all four roots. Mirrors `forestrie verify-grant`.
 *
 * Two verify functions rather than one with a union, because the leaf
 * commitment preimage differs — a payload receipt commits `SHA-256(payload)`,
 * a grant receipt commits the grant commitment hash. The `forestrie` CLI
 * makes the same split, as `verify` and `verify-grant`.
 *
 * Under the known-accumulator root the two differ only in the leaf hash.
 * `@forestrie/receipt-verify` has one
 * `verifyReceiptOfflineAgainstKnownAccumulator` for both receipt kinds, and
 * the caller supplies the leaf's inner hash: `SHA-256(payload)` for a payload
 * receipt, `grantCommitmentHashFromGrant(grant)` for a grant receipt. There
 * is no grant-specific entry point.
 */
import {
  decodeForestrieGrantCose,
  decodeTrustRootFromGenesis,
  entryIdHexToIdtimestampBe8,
  grantCommitmentHashFromGrant,
  verifyGrantReceiptOffline,
  verifyGrantReceiptOfflineWithKeys,
  type ReceiptVerifyResult,
} from "@forestrie/receipt-verify";
import {
  decodeCborDeterministic,
  decodeGrantPayload,
  type Grant,
} from "@forestrie/encoding";
import type { VerifyResult } from "./result.js";
import type { TrustRoot } from "./root.js";
import {
  assembleResult,
  importKnownLogKey,
  inputFailureResult,
  isDetachedPayload,
  remapKnownKeyFailure,
  verifyAtCheckpointChain,
  verifyAtKnownAccumulator,
  VerifyInputError,
} from "./verify-shared.js";

export type VerifyGrantReceiptInput = {
  receipt: Uint8Array;
  /** Forestrie-Grant COSE Sign1, or raw grant payload CBOR. */
  committedGrant: Uint8Array;
  /** 32 lowercase hex. Required when the grant is raw rather than COSE. */
  entryId?: string;
  trust: TrustRoot;
};

/**
 * Does the top-level CBOR item have Forestrie-Grant COSE Sign1's shape — a
 * 4-element array? A raw grant payload is always a CBOR map
 * (`grant-codec.ts`'s `encodeGrantPayload`/`encodeGrantPayloadV0Canonical`
 * both emit one), so an array of 4 can only ever be a Sign1 four-tuple, never
 * raw payload CBOR wearing COSE's clothes. Used to decide whether a
 * `decodeForestrieGrantCose` failure is real (the bytes claimed to be COSE
 * and were not valid) or just a sign the bytes were never COSE to begin with.
 */
function looksLikeForestrieGrantCose(bytes: Uint8Array): boolean {
  try {
    const raw: unknown = decodeCborDeterministic(bytes);
    return Array.isArray(raw) && raw.length === 4;
  } catch {
    return false;
  }
}

/**
 * Decode grant bytes: Forestrie-Grant COSE Sign1 first, raw payload CBOR
 * second — the same order and the same fallback as
 * `forestrie-cli/src/lib/verify-inputs.ts:decodeGrantBytes`, so the two agree
 * on what a caller may hand them.
 *
 * A bytestring shaped like a Sign1 four-tuple is dispatched to
 * `decodeForestrieGrantCose` and stays there: if it fails (FOR-580: the
 * embedded grant carries a retired key 7 or 8, say), that failure is
 * surfaced directly rather than swallowed and retried as raw payload CBOR.
 * The old code caught and retried on ANY COSE decode failure, which for a
 * COSE-shaped input meant retrying `decodeGrantPayload` against the same
 * four-element array — always a "must be a CBOR map" failure that named
 * neither the real defect nor the retired key, masking a genuine COSE-path
 * rejection behind a generic "neither COSE nor raw payload" message.
 */
function decodeCommittedGrant(
  bytes: Uint8Array,
  entryId: string | undefined,
): { grant: Grant; idtimestampBe8: Uint8Array } {
  if (looksLikeForestrieGrantCose(bytes)) {
    try {
      const decoded = decodeForestrieGrantCose(bytes);
      return {
        grant: decoded.grant,
        idtimestampBe8:
          entryId !== undefined
            ? entryIdHexToIdtimestampBe8(entryId)
            : decoded.idtimestampBe8,
      };
    } catch (err) {
      throw new VerifyInputError(
        `committedGrant is a Forestrie-Grant COSE Sign1 but failed to decode: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
  }
  let grant: Grant;
  try {
    grant = decodeGrantPayload(bytes);
  } catch (err) {
    throw new VerifyInputError(
      `committedGrant is neither a Forestrie-Grant COSE Sign1 nor a raw grant payload: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (entryId === undefined) {
    throw new VerifyInputError(
      "committedGrant is a raw grant payload (no embedded idtimestamp) — supply entryId",
    );
  }
  return { grant, idtimestampBe8: entryIdHexToIdtimestampBe8(entryId) };
}

async function rootKeysFor(trust: TrustRoot): Promise<CryptoKey[]> {
  const keys: CryptoKey[] = [];
  if (trust.root === "checkpoint-chain") {
    if (trust.keyXy !== undefined) {
      keys.push(await importKnownLogKey(trust.keyXy));
    }
    if (trust.genesis !== undefined) {
      const root = await decodeTrustRootFromGenesis(trust.genesis);
      // KS256 roots are a server-only concern; only P-256 roots can verify a
      // checkpoint's COSE signature here.
      if (root instanceof CryptoKey) keys.push(root);
    }
  }
  return keys;
}

export async function verifyGrantReceipt(
  input: VerifyGrantReceiptInput,
): Promise<VerifyResult> {
  const root = input.trust.root;
  const detachedPayload = isDetachedPayload(input.receipt);

  let grant: Grant;
  let idtimestampBe8: Uint8Array;
  try {
    ({ grant, idtimestampBe8 } = decodeCommittedGrant(
      input.committedGrant,
      input.entryId,
    ));
  } catch (err) {
    // The MCP layer validates its own inputs rather than trusting the
    // reference to fail cleanly: forestrie-cli crashes with an uncaught stack
    // trace when the committed grant is missing, even under --json.
    if (err instanceof VerifyInputError) {
      return inputFailureResult(root, "grant", err.message);
    }
    throw err;
  }

  try {
    switch (input.trust.root) {
      case "genesis": {
        const result = await verifyGrantReceiptOffline({
          genesisCbor: input.trust.genesis,
          receiptCbor: input.receipt,
          grant,
          idtimestampBe8,
        });
        return assembleResult({
          root,
          kind: "grant",
          result,
          detachedPayload,
        });
      }
      case "known-log-key": {
        const knownKey = await importKnownLogKey(input.trust.keyXy);
        const result: ReceiptVerifyResult = remapKnownKeyFailure(
          await verifyGrantReceiptOfflineWithKeys({
            receiptCbor: input.receipt,
            grant,
            idtimestampBe8,
            trustKeys: [knownKey],
          }),
        );
        return assembleResult({
          root,
          kind: "grant",
          result,
          detachedPayload,
        });
      }
      case "known-accumulator": {
        const { result, anchor } = await verifyAtKnownAccumulator({
          receiptCbor: input.receipt,
          idtimestampBe8,
          inner: await grantCommitmentHashFromGrant(grant),
          accumulatorBytes: input.trust.accumulator,
        });
        return assembleResult({
          root,
          kind: "grant",
          result,
          detachedPayload,
          anchor,
        });
      }
      case "checkpoint-chain": {
        const { result, anchor } = await verifyAtCheckpointChain({
          receiptCbor: input.receipt,
          idtimestampBe8,
          inner: await grantCommitmentHashFromGrant(grant),
          checkpoints: input.trust.checkpoints,
          rootKeys: await rootKeysFor(input.trust),
        });
        return assembleResult({
          root,
          kind: "grant",
          result,
          detachedPayload,
          anchor,
        });
      }
    }
  } catch (err) {
    if (err instanceof VerifyInputError) {
      return inputFailureResult(root, "grant", err.message);
    }
    throw err;
  }
}
