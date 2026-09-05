/**
 * Bundled-fixture loading. Part of the node adapter, not core: this is one of
 * exactly two modules allowed to touch `node:fs`
 * (the other is `resolve-input.ts`).
 *
 * The fixtures ship inside the tarball (`package.json#files` includes
 * `fixtures`) so `npx @forestrie/mcp-verify demo` and the
 * `forestrie://fixtures/golden/…` MCP resources work from a fresh install
 * with no repo checkout. `src/node/fixtures.ts` and `dist/node/fixtures.js`
 * sit at the same depth below the package root, so one relative path serves
 * both.
 *
 * `import.meta.dirname` is why `engines.node` is `>=20.11.0` and not
 * `>=20.0.0` — it landed in 20.11, and a package whose pitch is that its
 * claims are checkable does not get to make a false engines claim.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Grant } from "@forestrie/encoding";
import { encodeGrantPayloadV0Canonical } from "@forestrie/encoding";

/** The packaged `fixtures/` directory, resolved from this module's location. */
export const FIXTURES_DIR = join(import.meta.dirname, "..", "..", "fixtures");

export function fixturePath(relative: string): string {
  return join(FIXTURES_DIR, relative);
}

export function readFixture(relative: string): Uint8Array {
  return new Uint8Array(readFileSync(fixturePath(relative)));
}

export function readFixtureText(relative: string): string {
  return readFileSync(fixturePath(relative), "utf8");
}

/** FOR-289 golden manifest (`fixtures/golden/manifest.json`). */
export type GoldenManifest = {
  comment: string;
  logId: string;
  grantDataHex: string;
  idtimestampBe8Hex: string;
  genesisSha256: string;
  receiptSha256: string;
};

/** FOR-368 burial-bundle manifest (`fixtures/golden/burial/manifest.json`). */
export type BurialManifest = {
  comment: string;
  publicKeyXyHex: string;
  leafMmrIndex: string;
  leafHashHex: string;
  buriedPeakHex: string;
  finalAccumulatorHex: string[];
  checkpointFiles: string[];
  checkpointSha256: string[];
  receiptSha256: string;
};

export const GOLDEN_MANIFEST = JSON.parse(
  readFixtureText("golden/manifest.json"),
) as GoldenManifest;

export const BURIAL_MANIFEST = JSON.parse(
  readFixtureText("golden/burial/manifest.json"),
) as BurialManifest;

export function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, "");
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
    throw new Error(`not hex: '${hex}'`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function uuidToBytes(uuid: string): Uint8Array {
  return fromHex(uuid.replace(/-/g, ""));
}

/**
 * Rebuild the golden receipt's committed grant from the manifest.
 *
 * The field layout is canopy's
 * `receipt-verify/test/helpers/grant-receipt-fixture.ts` `grantWithData()`:
 * owner and target are the same log, flag byte 3 is 0x03 and byte 7 is 0x01,
 * heights are zero, and `grantData` is the manifest's 64 bytes. It is
 * reconstructed rather than frozen as a ninth file so `manifest.json` stays
 * the single source of truth — and `test/core/verify-grant-receipt.test.ts`
 * proves the reconstruction is right by verifying the frozen receipt against
 * the frozen genesis with it.
 */
export function goldenGrant(): Grant {
  const owner = uuidToBytes(GOLDEN_MANIFEST.logId);
  const flags = new Uint8Array(8);
  flags[3] = 0x03;
  flags[7] = 0x01;
  return {
    logId: owner,
    ownerLogId: owner,
    grant: flags,
    maxHeight: 0,
    minGrowth: 0,
    grantData: fromHex(GOLDEN_MANIFEST.grantDataHex),
  };
}

/**
 * The golden committed grant as raw Forestrie-Grant v0 payload CBOR — the
 * exact bytes `verify_grant_receipt`'s `committedGrant` input takes, and the
 * exact bytes `forestrie verify-grant --committed-grant-file` reads.
 */
export function goldenCommittedGrant(): Uint8Array {
  return encodeGrantPayloadV0Canonical(goldenGrant());
}

/** 32 lowercase hex: idtimestamp_be8 ‖ mmrIndex_be8. Verify uses the first half. */
export function goldenEntryId(): string {
  return `${GOLDEN_MANIFEST.idtimestampBe8Hex}0000000000000001`;
}
