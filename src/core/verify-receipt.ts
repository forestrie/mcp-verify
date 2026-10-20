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
  type Ks256Attestation,
  type ReceiptVerifyResult,
  type RootVerifyKey,
} from "@forestrie/receipt-verify";
import type { VerifyResult } from "./result.js";
import type { TrustRoot } from "./root.js";
import {
  assembleResult,
  attestationInputs,
  attestationOutcome,
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
  /**
   * Several attestations, for a Safe that rotated its delegate (one
   * certificate per delegate, one attestation per certificate). Combined with
   * `ks256Attestation` when both are given. Every one is reported as used or
   * unused (with the reason) in the result.
   */
  ks256Attestations?: readonly Uint8Array[];
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
    const plan = planAttestation(input.trust, attestationInputs(input));
    switch (input.trust.root) {
      case "genesis": {
        const genesisCbor = input.trust.genesis;
        const call = (atts: Ks256Attestation[]) =>
          verifyReceiptOffline({
            genesisCbor,
            receiptCbor: input.receipt,
            payload: input.payload,
            idtimestampBe8,
            ...(atts.length > 0 ? { ks256Attestations: atts } : {}),
          });
        const result = await call(plan.attestations);
        return assembleResult({
          root,
          kind: "payload",
          result,
          detachedPayload,
          ...(await attestationOutcome(
            plan,
            result,
            call,
            () => decodeTrustRootFromGenesis(genesisCbor),
            input.receipt,
          )),
        });
      }
      case "known-log-key": {
        const knownKey = await resolveKnownLogKey(input.trust);
        const call = async (
          atts: Ks256Attestation[],
        ): Promise<ReceiptVerifyResult> =>
          remapKnownKeyFailure(
            await verifyReceiptOfflineWithKeys({
              receiptCbor: input.receipt,
              payload: input.payload,
              idtimestampBe8,
              trustKeys: [knownKey],
              ...(atts.length > 0 ? { ks256Attestations: atts } : {}),
              ...(plan.forestGenesisCbor !== undefined
                ? { forestGenesisCbor: plan.forestGenesisCbor }
                : {}),
            }),
          );
        const result = await call(plan.attestations);
        return assembleResult({
          root,
          kind: "payload",
          result,
          detachedPayload,
          ...(await attestationOutcome(
            plan,
            result,
            call,
            async () => knownKey,
            input.receipt,
          )),
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
        const rootKeys = await rootKeysFor(input.trust);
        const chain = await verifyAtCheckpointChain({
          receiptCbor: input.receipt,
          idtimestampBe8,
          inner: await innerHash(input.payload),
          checkpoints: input.trust.checkpoints,
          rootKeys,
          attestation: plan,
        });
        return assembleResult({
          root,
          kind: "payload",
          result: chain.result,
          detachedPayload,
          ...(chain.anchor !== undefined ? { anchor: chain.anchor } : {}),
          chainStage: chain.chainStage,
          detail: chain.detail,
          failedLink: chain.failedLink,
          ks256Attestations: chain.ks256Attestations,
          attestationUnusedLabel: chain.attestationUnusedLabel,
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
