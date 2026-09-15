/**
 * `scripts/assert-server-json.mjs`'s `checkServerJson` — the registry-listing
 * version guard plus the registry schema's 100-character caps on
 * `description` and `title` (ported from `@forestrie/mcp-resolve`).
 *
 * The script lives under `scripts/`, not `src/`, so it is exercised directly
 * via dynamic import rather than through the package's public surface, the
 * same convention `test/node/self-register.test.ts` uses. `checkServerJson`
 * is pure over parsed objects, so no filesystem or process spawn is needed
 * to cover every branch.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkServerJson } from "../../scripts/assert-server-json.mjs";

const REPO_ROOT = join(import.meta.dirname, "..", "..");

function readJson(path: string) {
  return JSON.parse(readFileSync(path, "utf8"));
}

// The real package.json/server.json, read once — also proves the checked-in
// files agree, which `pnpm run check:server-json` already asserts on every
// `pnpm test`, but doubling it here keeps this test file self-contained.
const REAL_PKG = readJson(join(REPO_ROOT, "package.json"));
const REAL_SERVER = readJson(join(REPO_ROOT, "server.json"));

describe("checkServerJson — version/name agreement", () => {
  it("the real package.json and server.json agree", () => {
    expect(checkServerJson(REAL_PKG, REAL_SERVER)).toEqual([]);
  });

  it("a server.json#version mismatch is refused", () => {
    const server = { ...REAL_SERVER, version: "0.0.0-mismatch" };
    const failures = checkServerJson(REAL_PKG, server);
    expect(failures).toContain(
      `server.json#version is "0.0.0-mismatch" but package.json#version is "${REAL_PKG.version}"`,
    );
  });

  it("a server.json#name / package.json#mcpName mismatch is refused", () => {
    const server = { ...REAL_SERVER, name: "dev.forestrie/not-verify" };
    const failures = checkServerJson(REAL_PKG, server);
    expect(failures).toContain(
      `server.json#name is "dev.forestrie/not-verify" but package.json#mcpName is "${REAL_PKG.mcpName}"`,
    );
  });
});

describe("checkServerJson — registry length caps", () => {
  it("a 101-character description fails the check", () => {
    const server = { ...REAL_SERVER, description: "x".repeat(101) };
    const failures = checkServerJson(REAL_PKG, server);
    expect(failures).toContain(
      "server.json#description is 101 characters; the registry schema allows at most 100",
    );
  });

  it("a 100-character description passes", () => {
    const server = { ...REAL_SERVER, description: "x".repeat(100) };
    expect(checkServerJson(REAL_PKG, server)).toEqual([]);
  });

  it("an empty description fails the check", () => {
    const server = { ...REAL_SERVER, description: "" };
    const failures = checkServerJson(REAL_PKG, server);
    expect(failures).toContain("server.json#description is missing or empty");
  });

  it("a 101-character title fails the check", () => {
    const server = { ...REAL_SERVER, title: "x".repeat(101) };
    const failures = checkServerJson(REAL_PKG, server);
    expect(failures).toContain(
      "server.json#title is 101 characters; the registry schema allows at most 100",
    );
  });

  it("a 100-character title passes", () => {
    const server = { ...REAL_SERVER, title: "x".repeat(100) };
    expect(checkServerJson(REAL_PKG, server)).toEqual([]);
  });

  it("a missing title is fine — title is optional", () => {
    expect(REAL_SERVER.title).toBeUndefined();
    expect(checkServerJson(REAL_PKG, REAL_SERVER)).toEqual([]);
  });
});
