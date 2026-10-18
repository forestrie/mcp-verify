/**
 * Payload receipt verification, all four roots. Mirrors `forestrie verify` —
 * the generic, SCITT-compatible path: the leaf commits
 * `SHA-256(idtimestamp ‖ SHA-256(payload))` and the caller passes the EXACT
 * registered payload bytes.
 *
 * Why this and `verify-grant-receipt.ts` are separate functions: see that
 * file's header.
 */
import {
  decodeTrustRootFromGenesis,
  entryIdHexToIdtimestampBe8,
  verifyReceiptOffline,
  verifyReceiptOfflineWithKeys,
  type ReceiptVerifyResult,
  type RootVerifyKey,
} from "@forestrie/receipt-verify";
import type { VerifyResult } from "./result.js";
import type { TrustRoot } from "./root.js";
import {
  assembleResult,
  attestationReport,
  importKnownLogKey,
  inputFailureResult,
  isDetachedPayload,
  planAttestation,
  remapKnownKeyFailure,
  resolveKnownLogKey,
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
  trust: TrustRoot;
  /**
   * Optional ERC-1271 attestation artifact (`encodeKs256Attestation` bytes)
   * for a KS256 CONTRACT root. Usable only with the `genesis` and
   * `known-log-key` roots. Fetched elsewhere; never fetched here.
   */
  ks256Attestation?: Uint8Array;
};

/** SHA-256 over the payload — the leaf's inner ContentHash. */
async function innerHash(payload: Uint8Array): Promise<Uint8Array> {
  // The copy pins the generic to ArrayBuffer for the dom BufferSource type.
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", new Uint8Array(payload)),
  );
}

async function rootKeysFor(trust: TrustRoot): Promise<RootVerifyKey[]> {
  const keys: RootVerifyKey[] = [];
  if (trust.root === "checkpoint-chain") {
    if (trust.keyXy !== undefined) {
      keys.push(await importKnownLogKey(trust.keyXy));
    }
    if (trust.genesis !== undefined) {
      // ES256 or KS256: passed through whole, never filtered.
      keys.push(await decodeTrustRootFromGenesis(trust.genesis));
    }
  }
  return keys;
}

export async function verifyReceipt(
  input: VerifyReceiptInput,
): Promise<VerifyResult> {
  const root = input.trust.root;
  const detachedPayload = isDetachedPayload(input.receipt);

  let idtimestampBe8: Uint8Array;
  try {
    idtimestampBe8 = entryIdHexToIdtimestampBe8(input.entryId);
  } catch (err) {
    return inputFailureResult(
      root,
      "payload",
      `entryId must be 32 lowercase hex (idtimestamp_be8 ‖ mmrIndex_be8): ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  try {
    const plan = planAttestation(input.trust, input.ks256Attestation);
    switch (input.trust.root) {
      case "genesis": {
        const result = await verifyReceiptOffline({
          genesisCbor: input.trust.genesis,
          receiptCbor: input.receipt,
          payload: input.payload,
          idtimestampBe8,
          ...(plan.attestation !== undefined
            ? { ks256Attestation: plan.attestation }
            : {}),
        });
        return assembleResult({
          root,
          kind: "payload",
          result,
          detachedPayload,
          ks256Attestation: attestationReport(plan, result),
        });
      }
      case "known-log-key": {
        const knownKey = await resolveKnownLogKey(input.trust);
        const result: ReceiptVerifyResult = remapKnownKeyFailure(
          await verifyReceiptOfflineWithKeys({
            receiptCbor: input.receipt,
            payload: input.payload,
            idtimestampBe8,
            trustKeys: [knownKey],
            ...(plan.attestation !== undefined
              ? { ks256Attestation: plan.attestation }
              : {}),
            ...(plan.forestGenesisCbor !== undefined
              ? { forestGenesisCbor: plan.forestGenesisCbor }
              : {}),
          }),
        );
        return assembleResult({
          root,
          kind: "payload",
          result,
          detachedPayload,
          ks256Attestation: attestationReport(plan, result),
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
          root,
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
          root,
          kind: "payload",
          result,
          detachedPayload,
          anchor,
        });
      }
    }
  } catch (err) {
    if (err instanceof VerifyInputError) {
      return inputFailureResult(root, "payload", err.message);
    }
    throw err;
  }
}
