/**
 * The `node:fs` boundary. Base64 in, or a path read from disk. Nothing else
 * in `src/node` reads files except `fixtures.ts`, which reads only the
 * package's own bundled fixtures.
 *
 * This module validates aggressively and errors clearly, and that is a
 * deliberate response to the `forestrie` CLI: `forestrie verify-grant`
 * crashes with an uncaught stack trace when a required argument is missing,
 * even under `--json`. An MCP tool
 * that did the same would hand an agent a stack trace where it expected a
 * tool error. So the MCP layer validates its own inputs rather than trusting
 * the reference to fail cleanly.
 */
import { readFileSync } from "node:fs";
import type { TrustRoot } from "../core/index.js";

export class InputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InputError";
  }
}

/** Bytes cross the MCP boundary as base64 — `b64`, or its alias `base64`
 *  (the name `@forestrie/mcp-resolve` documented first; accepted here
 *  permanently so a caller who learned either server's shape is not
 *  turned away by the other) — and stdio additionally accepts a path. */
export type BytesInput =
  { b64: string } | { base64: string } | { path: string };

/**
 * Strict base64. `Buffer.from(s, "base64")` silently ignores anything it does
 * not understand, so `"not base64 at all!"` decodes to a few plausible bytes
 * and then fails much later as `receipt_malformed` — a verification-shaped
 * error for what is really a typo. Reject the input here instead.
 */
function decodeBase64(
  value: string,
  what: string,
  key: "b64" | "base64",
): Uint8Array {
  const trimmed = value.trim();
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(trimmed) || trimmed.length === 0) {
    throw new InputError(
      `${what}.${key} is not valid base64 (standard alphabet, optional '=' padding)`,
    );
  }
  const bytes = new Uint8Array(Buffer.from(trimmed, "base64"));
  if (bytes.length === 0) {
    throw new InputError(`${what}.${key} decoded to 0 bytes`);
  }
  // Round-trip guard: catches truncated / mis-padded input that Buffer would
  // otherwise accept by discarding the incomplete trailing group.
  if (
    Buffer.from(bytes).toString("base64").replace(/=+$/, "") !==
    trimmed.replace(/=+$/, "")
  ) {
    throw new InputError(
      `${what}.${key} is not canonical base64 (it does not round-trip)`,
    );
  }
  return bytes;
}

export function resolveBytes(input: BytesInput, what = "input"): Uint8Array {
  if ("b64" in input) {
    return decodeBase64(input.b64, what, "b64");
  }
  if ("base64" in input) {
    return decodeBase64(input.base64, what, "base64");
  }
  if (input.path.trim() === "") {
    throw new InputError(`${what}.path is empty`);
  }
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(readFileSync(input.path));
  } catch (err) {
    throw new InputError(
      `cannot read ${what}.path '${input.path}': ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (bytes.length === 0) {
    throw new InputError(`${what}.path '${input.path}' is empty (0 bytes)`);
  }
  return bytes;
}

/** The wire form of a trust root: the same union, with bytes as BytesInput. */
export type TrustRootInput =
  | { root: "genesis"; genesis: BytesInput }
  | { root: "known-log-key"; keyXy: BytesInput }
  | {
      root: "known-accumulator";
      accumulator: BytesInput;
      massif?: BytesInput;
      consistencyProof?: BytesInput;
    }
  | {
      root: "checkpoint-chain";
      checkpoints: BytesInput[];
      genesis?: BytesInput;
      keyXy?: BytesInput;
    };

/**
 * Resolve every byte-shaped field of a root. `exactOptionalPropertyTypes` is
 * on, so optional fields are added conditionally rather than set to
 * `undefined` — the difference matters to the core's union narrowing.
 */
export function resolveRoot(input: TrustRootInput): TrustRoot {
  switch (input.root) {
    case "genesis":
      return {
        root: "genesis",
        genesis: resolveBytes(input.genesis, "trust.genesis"),
      };
    case "known-log-key":
      return {
        root: "known-log-key",
        keyXy: resolveBytes(input.keyXy, "trust.keyXy"),
      };
    case "known-accumulator": {
      const out: TrustRoot = {
        root: "known-accumulator",
        accumulator: resolveBytes(input.accumulator, "trust.accumulator"),
      };
      if (input.massif !== undefined) {
        out.massif = resolveBytes(input.massif, "trust.massif");
      }
      if (input.consistencyProof !== undefined) {
        out.consistencyProof = resolveBytes(
          input.consistencyProof,
          "trust.consistencyProof",
        );
      }
      return out;
    }
    case "checkpoint-chain": {
      if (input.checkpoints.length === 0) {
        throw new InputError("trust.checkpoints must not be empty");
      }
      const out: TrustRoot = {
        root: "checkpoint-chain",
        checkpoints: input.checkpoints.map((c, i) =>
          resolveBytes(c, `trust.checkpoints[${i}]`),
        ),
      };
      if (input.genesis !== undefined) {
        out.genesis = resolveBytes(input.genesis, "trust.genesis");
      }
      if (input.keyXy !== undefined) {
        out.keyXy = resolveBytes(input.keyXy, "trust.keyXy");
      }
      if (out.genesis === undefined && out.keyXy === undefined) {
        throw new InputError(
          "the checkpoint-chain root needs a trust root: supply trust.genesis or trust.keyXy",
        );
      }
      return out;
    }
  }
}
