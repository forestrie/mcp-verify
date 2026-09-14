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
 *   - server.json#description     non-empty, at most 100 characters (registry schema)
 *   - server.json#title           if present, at most 100 characters (registry schema)
 *
 * A mismatch on any of the first three is a hard failure, not a warning — an
 * out-of-date server.json is a false claim to a registry an outside agent
 * queries directly, and package.json#mcpName is what the registry checks
 * to verify npm package ownership (official-registry-requirements.md).
 *
 * The registry schema (2025-12-11) caps `description` and `title` at 100
 * characters and requires a non-empty description; mcp-publisher only finds
 * that out at publish time with a 422, after `npm publish` has already
 * shipped the version — that is exactly what happened to
 * @forestrie/mcp-resolve's v0.1.1 (plan-2609-05 phase 3). Fail here instead,
 * before a version is ever published (plan-2609-07 step 3.1).
 *
 * Wired into both `pnpm test` (ci.yml) and publish.yml's guard step, exactly
 * like scripts/assert-publish-version.sh and check-encoding-single-copy.mjs.
 *
 * Usage: node scripts/assert-server-json.mjs [repoDir]
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const DESCRIPTION_MAX = 100;

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

/**
 * Pure check over the parsed `package.json` and `server.json` objects.
 * Returns an array of failure strings (empty when everything agrees).
 * Exported so the unit project can exercise every branch — including the
 * length caps — without spawning a process or touching the filesystem.
 */
export function checkServerJson(pkg, server) {
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

  // The registry schema (2025-12-11) caps `description` and `title` at 100
  // characters and requires a non-empty description; mcp-publisher only
  // finds out at publish time with a 422, after `npm publish` has already
  // shipped the version (@forestrie/mcp-resolve v0.1.1, plan-2609-05 phase
  // 3). Fail here instead.
  if (
    typeof server.description !== "string" ||
    server.description.length === 0
  ) {
    failures.push("server.json#description is missing or empty");
  } else if (server.description.length > DESCRIPTION_MAX) {
    failures.push(
      `server.json#description is ${server.description.length} characters; the registry schema allows at most ${DESCRIPTION_MAX}`,
    );
  }
  if (
    typeof server.title === "string" &&
    server.title.length > DESCRIPTION_MAX
  ) {
    failures.push(
      `server.json#title is ${server.title.length} characters; the registry schema allows at most ${DESCRIPTION_MAX}`,
    );
  }

  return failures;
}

// ---------------------------------------------------------------------------
// CLI bootstrap
// ---------------------------------------------------------------------------

const isMain =
  process.argv[1] !== undefined &&
  fileURLToPath(import.meta.url) === process.argv[1];

if (isMain) {
  const root = process.argv[2] ?? process.cwd();
  const pkg = readJson(join(root, "package.json"));
  const server = readJson(join(root, "server.json"));

  const failures = checkServerJson(pkg, server);

  if (failures.length > 0) {
    console.error("assert-server-json FAILED:");
    for (const f of failures) console.error(`  - ${f}`);
    process.exit(1);
  }

  console.log(
    `assert-server-json OK: server.json and package.json agree at ${pkg.version} (${pkg.mcpName}).`,
  );
}
