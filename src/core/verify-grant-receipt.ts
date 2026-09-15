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
import { decodeGrantPayload, type Grant } from "@forestrie/encoding";
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
 * Decode grant bytes: Forestrie-Grant COSE Sign1 first, raw payload CBOR
 * second — the same order and the same fallback as
 * `forestrie-cli/src/lib/verify-inputs.ts:decodeGrantBytes`, so the two agree
 * on what a caller may hand them.
 */
function decodeCommittedGrant(
  bytes: Uint8Array,
  entryId: string | undefined,
): { grant: Grant; idtimestampBe8: Uint8Array } {
  try {
    const decoded = decodeForestrieGrantCose(bytes);
    return {
      grant: decoded.grant,
      idtimestampBe8:
        entryId !== undefined
          ? entryIdHexToIdtimestampBe8(entryId)
          : decoded.idtimestampBe8,
    };
  } catch {
    // Not a Forestrie-Grant COSE Sign1 — fall through to raw payload CBOR.
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
    // trace when the committed grant is missing, even under --json
    // (plan-2609-02 "What changed on contact" 3).
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
