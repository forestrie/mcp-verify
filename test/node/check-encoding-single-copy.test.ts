/**
 * `findCopies` (scripts/check-encoding-single-copy.mjs) must see a second
 * copy of `@forestrie/encoding` nested inside the first copy's own
 * node_modules (npm's fallback layout), and a clean tree must show one.
 */
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { findCopies } from "../../scripts/check-encoding-single-copy.mjs";

let scratchDir: string | undefined;

function writePkg(dir: string, name: string, version: string) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name, version }));
}

afterEach(() => {
  if (scratchDir !== undefined) {
    rmSync(scratchDir, { recursive: true, force: true });
    scratchDir = undefined;
  }
});

describe("check:encoding-single-copy — findCopies", () => {
  it("passes a clean npm-style tree: one version", () => {
    scratchDir = mkdtempSync(join(tmpdir(), "single-copy-clean-"));
    const nm = join(scratchDir, "node_modules", "@forestrie");
    writePkg(join(nm, "encoding"), "@forestrie/encoding", "0.8.0");
    expect([...findCopies(scratchDir).keys()]).toEqual(["0.8.0"]);
  });

  it("reports a copy nested inside the first copy's own node_modules", () => {
    scratchDir = mkdtempSync(join(tmpdir(), "single-copy-nested-"));
    const nm = join(scratchDir, "node_modules", "@forestrie");
    writePkg(join(nm, "encoding"), "@forestrie/encoding", "0.8.0");
    writePkg(
      join(nm, "encoding", "node_modules", "@forestrie", "encoding"),
      "@forestrie/encoding",
      "0.9.0",
    );
    expect([...findCopies(scratchDir).keys()].sort()).toEqual([
      "0.8.0",
      "0.9.0",
    ]);
  });
});
