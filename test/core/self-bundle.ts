/**
 * Loading the frozen self-registration bundle, `test/fixtures/self-bundle/`
 * (plan-2609-02 steps 2.4/2.5). A REAL bundle, captured once against lane A
 * and frozen — read `test/fixtures/self-bundle/PROVENANCE.md` before
 * touching anything here. Tamper variants are generated in-test from these
 * bytes, never committed, exactly the `test/core/tamper.ts` pattern.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { SelfBundle } from "../../src/core/index.js";

export const SELF_BUNDLE_DIR = join(
  new URL("../fixtures/self-bundle/", import.meta.url).pathname,
);

export type SelfBundleManifest = {
  comment: string;
  generatedAt: string;
  files: Record<string, string>;
};

function readBytes(name: string): Uint8Array {
  return new Uint8Array(readFileSync(join(SELF_BUNDLE_DIR, name)));
}

function readText(name: string): string {
  return readFileSync(join(SELF_BUNDLE_DIR, name), "utf8");
}

export const SELF_BUNDLE_MANIFEST = JSON.parse(
  readText("manifest.json"),
) as SelfBundleManifest;

/** The frozen bundle, as a fresh `SelfBundle` (each call re-reads from disk,
 *  so a caller mutating one field's bytes for a tamper case never affects
 *  another). */
export function readSelfBundle(): SelfBundle {
  return {
    provenanceJson: readBytes("provenance.json"),
    statementCose: readBytes("statement.cose"),
    receipt: readBytes("receipt.cbor"),
    genesis: readBytes("genesis.cbor"),
    logKeyXy: new Uint8Array(
      Buffer.from(readText("log-key.xy.b64").trim(), "base64"),
    ),
    entryId: readText("entry-id.txt").trim(),
  };
}
