/**
 * The frozen-bytes pin. Modelled on canopy
 * receipt-verify/test/golden-vectors.test.ts:39-44, extended to cover the
 * burial chain and the packaging promise.
 *
 * This is what makes "vendored, frozen bytes" true rather than aspirational:
 * an accidental `prettier --write` over a `.cbor`, a line-ending mangle, or a
 * well-meant regeneration all fail here. Regeneration is a deliberate act
 * (fixtures/PROVENANCE.md), never a casual fix for a red test.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  BURIAL_MANIFEST,
  GOLDEN_MANIFEST,
  fixturePath,
  readFixture,
} from "../../src/node/fixtures.js";
import { SELF_BUNDLE_DIR, SELF_BUNDLE_MANIFEST } from "./self-bundle.js";

const sha256 = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

const repoRoot = new URL("../../", import.meta.url).pathname;

describe("golden vectors (frozen bytes)", () => {
  it("grant-genesis.cbor matches manifest.genesisSha256", () => {
    expect(sha256(readFixture("golden/grant-genesis.cbor"))).toBe(
      GOLDEN_MANIFEST.genesisSha256,
    );
  });

  it("grant-receipt.cbor matches manifest.receiptSha256", () => {
    expect(sha256(readFixture("golden/grant-receipt.cbor"))).toBe(
      GOLDEN_MANIFEST.receiptSha256,
    );
  });

  it("the burial receipt matches burial/manifest.receiptSha256", () => {
    expect(sha256(readFixture("golden/burial/burial-receipt.cbor"))).toBe(
      BURIAL_MANIFEST.receiptSha256,
    );
  });

  it("every retained checkpoint matches its recorded digest", () => {
    expect(BURIAL_MANIFEST.checkpointFiles.length).toBe(4);
    BURIAL_MANIFEST.checkpointFiles.forEach((file, i) => {
      expect(sha256(readFixture(`golden/burial/${file}`))).toBe(
        BURIAL_MANIFEST.checkpointSha256[i],
      );
    });
  });

  it("the manifests carry the fields the rest of the suite reads", () => {
    expect(GOLDEN_MANIFEST.logId).toBe("660e8400-e29b-41d4-a716-446655440001");
    expect(GOLDEN_MANIFEST.grantDataHex).toHaveLength(128);
    expect(GOLDEN_MANIFEST.idtimestampBe8Hex).toHaveLength(16);
    expect(BURIAL_MANIFEST.finalAccumulatorHex.length).toBeGreaterThan(0);
  });
});

describe("the self-registration bundle (frozen bytes, test/fixtures/self-bundle)", () => {
  /**
   * A real bundle captured once against lane A (see PROVENANCE.md in that
   * directory), frozen the same way the golden vectors above are: this pin
   * is what makes "these bytes never move" true rather than aspirational.
   */
  it("every bundled file matches manifest.json's sha256", () => {
    for (const [name, expected] of Object.entries(
      SELF_BUNDLE_MANIFEST.files,
    )) {
      const bytes = readFileSync(join(SELF_BUNDLE_DIR, name));
      expect(sha256(new Uint8Array(bytes)), name).toBe(expected);
    }
  });

  it("the manifest names exactly the six bundle files verifySelf needs", () => {
    expect(Object.keys(SELF_BUNDLE_MANIFEST.files).sort()).toEqual([
      "entry-id.txt",
      "genesis.cbor",
      "log-key.xy.b64",
      "provenance.json",
      "receipt.cbor",
      "statement.cose",
    ]);
  });
});

describe("the fixtures actually ship", () => {
  /**
   * The fixtures-as-MCP-resources promise is a packaging promise. The
   * full tarball check lives in the publish-dry-run CI job; this is the
   * cheap half that fails in a normal `pnpm test` when someone edits `files`.
   */
  it("package.json#files includes fixtures", () => {
    const pkg = JSON.parse(
      readFileSync(join(repoRoot, "package.json"), "utf8"),
    ) as { files: string[] };
    expect(pkg.files).toContain("fixtures");
    expect(pkg.files).toContain("bin");
    expect(pkg.files).toContain("dist");
  });

  it("every fixture the resource layer advertises resolves on disk", () => {
    const advertised = [
      "golden/manifest.json",
      "golden/grant-genesis.cbor",
      "golden/grant-receipt.cbor",
      "golden/burial/manifest.json",
      "golden/burial/burial-receipt.cbor",
      ...BURIAL_MANIFEST.checkpointFiles.map((f) => `golden/burial/${f}`),
    ];
    for (const rel of advertised) {
      expect(() => readFileSync(fixturePath(rel))).not.toThrow();
    }
  });
});
