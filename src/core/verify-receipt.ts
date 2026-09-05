/**
 * Payload receipt verification, all four rungs. Mirrors `forestrie verify` —
 * the generic, SCITT-compatible path: the leaf commits
 * `SHA-256(idtimestamp ‖ SHA-256(payload))` and the caller passes the EXACT
 * registered payload bytes.
 */
import {
  decodeTrustRootFromGenesis,
  entryIdHexToIdtimestampBe8,
  verifyReceiptOffline,
  verifyReceiptOfflineWithKeys,
  type ReceiptVerifyResult,
} from "@forestrie/receipt-verify";
import type { VerifyResult } from "./result.js";
import type { TrustRung } from "./rung.js";
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

export type VerifyReceiptInput = {
  receipt: Uint8Array;
  /** The EXACT registered payload whose SHA-256 is the leaf ContentHash. */
  payload: Uint8Array;
  /** 32 lowercase hex = idtimestamp_be8 ‖ mmrIndex_be8. */
  entryId: string;
  trust: TrustRung;
};

/** SHA-256 over the payload — the leaf's inner ContentHash. */
async function innerHash(payload: Uint8Array): Promise<Uint8Array> {
  // The copy pins the generic to ArrayBuffer for the dom BufferSource type.
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", new Uint8Array(payload)),
  );
}

async function rootKeysFor(trust: TrustRung): Promise<CryptoKey[]> {
  const keys: CryptoKey[] = [];
  if (trust.rung === "checkpoint-chain") {
    if (trust.keyXy !== undefined) {
      keys.push(await importKnownLogKey(trust.keyXy));
    }
    if (trust.genesis !== undefined) {
      const root = await decodeTrustRootFromGenesis(trust.genesis);
      if (root instanceof CryptoKey) keys.push(root);
    }
  }
  return keys;
}

export async function verifyReceipt(
  input: VerifyReceiptInput,
): Promise<VerifyResult> {
  const rung = input.trust.rung;
  const detachedPayload = isDetachedPayload(input.receipt);

  let idtimestampBe8: Uint8Array;
  try {
    idtimestampBe8 = entryIdHexToIdtimestampBe8(input.entryId);
  } catch (err) {
    return inputFailureResult(
      rung,
      "payload",
      `entryId must be 32 lowercase hex (idtimestamp_be8 ‖ mmrIndex_be8): ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  try {
    switch (input.trust.rung) {
      case "genesis": {
        const result = await verifyReceiptOffline({
          genesisCbor: input.trust.genesis,
          receiptCbor: input.receipt,
          payload: input.payload,
          idtimestampBe8,
        });
        return assembleResult({
          rung,
          kind: "payload",
          result,
          detachedPayload,
        });
      }
      case "known-log-key": {
        const knownKey = await importKnownLogKey(input.trust.keyXy);
        const result: ReceiptVerifyResult = remapKnownKeyFailure(
          await verifyReceiptOfflineWithKeys({
            receiptCbor: input.receipt,
            payload: input.payload,
            idtimestampBe8,
            trustKeys: [knownKey],
          }),
        );
        return assembleResult({
          rung,
          kind: "payload",
          result,
          detachedPayload,
        });
      }
      case "known-accumulator": {
        const { result, anchor } = await verifyAtKnownAccumulator({
          receiptCbor: input.receipt,
          idtimestampBe8,
          inner: await innerHash(input.payload),
          accumulatorBytes: input.trust.accumulator,
        });
        return assembleResult({
          rung,
          kind: "payload",
          result,
          detachedPayload,
          anchor,
        });
      }
      case "checkpoint-chain": {
        const { result, anchor } = await verifyAtCheckpointChain({
          receiptCbor: input.receipt,
          idtimestampBe8,
          inner: await innerHash(input.payload),
          checkpoints: input.trust.checkpoints,
          rootKeys: await rootKeysFor(input.trust),
        });
        return assembleResult({
          rung,
          kind: "payload",
          result,
          detachedPayload,
          anchor,
        });
      }
    }
  } catch (err) {
    if (err instanceof VerifyInputError) {
      return inputFailureResult(rung, "payload", err.message);
    }
    throw err;
  }
}
