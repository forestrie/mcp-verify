#!/usr/bin/env node
/**
 * plan-2609-02 step 3.3 — the registry-listing version guard.
 *
 * server.json's `version` (and `packages[0].version`) cannot be read from
 * package.json at build time — it is a static file the MCP registry fetches
 * over HTTP, not a build artifact — so a version bump can silently leave it
 * behind. This script is the release gate that makes that impossible:
 *
 *   - server.json#version         === package.json#version
 *   - server.json#packages[0].version === package.json#version
 *   - server.json#name            === package.json#mcpName
 *
 * A mismatch on any of the three is a hard failure, not a warning — an
 * out-of-date server.json is a false claim to a registry an outside agent
 * queries directly, and package.json#mcpName is what the registry checks
 * to verify npm package ownership (official-registry-requirements.md).
 *
 * Wired into both `pnpm test` (ci.yml) and publish.yml's guard step, exactly
 * like scripts/assert-publish-version.sh and check-encoding-single-copy.mjs.
 *
 * Usage: node scripts/assert-server-json.mjs [repoDir]
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = process.argv[2] ?? process.cwd();

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

const pkg = readJson(join(root, "package.json"));
const server = readJson(join(root, "server.json"));

const failures = [];

if (server.version !== pkg.version) {
  failures.push(
    `server.json#version is "${server.version}" but package.json#version is "${pkg.version}"`,
  );
}

const firstPackage = server.packages?.[0];
if (!firstPackage) {
  failures.push("server.json#packages[0] is missing");
} else if (firstPackage.version !== pkg.version) {
  failures.push(
    `server.json#packages[0].version is "${firstPackage.version}" but package.json#version is "${pkg.version}"`,
  );
}

if (!pkg.mcpName) {
  failures.push(
    "package.json#mcpName is missing; the registry checks it to verify npm package ownership",
  );
} else if (server.name !== pkg.mcpName) {
  failures.push(
    `server.json#name is "${server.name}" but package.json#mcpName is "${pkg.mcpName}"`,
  );
}

if (failures.length > 0) {
  console.error("assert-server-json FAILED:");
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}

console.log(
  `assert-server-json OK: server.json and package.json agree at ${pkg.version} (${pkg.mcpName}).`,
);
