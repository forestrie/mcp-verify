/**
 * npm-install resolution for `@forestrie/forestrie-cli`, which
 * `scripts/self-register.mjs` runs at release time (delegate,
 * sign-statement, register).
 *
 * The CLI is installed from npm at the exact `FORESTRIE_CLI_VERSION` below,
 * into a version-keyed cache, and run under plain `node`: no Bun, no
 * per-platform binary, and npm's registry integrity check on install.
 *
 * `--no-save --prefix` never touches this repo's own `package.json` or pnpm
 * lockfile: `@forestrie/forestrie-cli` is not, and must not become, a
 * dependency of this package.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";

/** Bump deliberately: every release registers its provenance with it. */
export const FORESTRIE_CLI_VERSION = "0.9.0";

/** The version-keyed scratch install root under `repoRoot`. */
export function cliCacheDir(repoRoot, version = FORESTRIE_CLI_VERSION) {
  return join(
    repoRoot,
    "node_modules",
    ".cache",
    "forestrie-cli-npm",
    version,
  );
}

/** The installed package's node-runnable entry point. */
export function cliEntryPath(repoRoot, version = FORESTRIE_CLI_VERSION) {
  return join(
    cliCacheDir(repoRoot, version),
    "node_modules",
    "@forestrie",
    "forestrie-cli",
    "dist",
    "cli.js",
  );
}

/**
 * Ensure the pinned `@forestrie/forestrie-cli` is installed into the
 * version-keyed cache under `repoRoot`, and return the path to its
 * `dist/cli.js` entry point. Idempotent: skips the install once that entry
 * exists, so repeated calls (or a warm CI cache) never re-hit the registry.
 * Throws a plain `Error` on install failure — callers translate that into
 * their own error type.
 */
export function ensureForestrieCliInstalled(
  repoRoot,
  { version = FORESTRIE_CLI_VERSION, log } = {},
) {
  const entry = cliEntryPath(repoRoot, version);
  if (existsSync(entry)) return entry;

  const installDir = cliCacheDir(repoRoot, version);
  log?.(`installing @forestrie/forestrie-cli@${version} into ${installDir}`);
  mkdirSync(installDir, { recursive: true });
  const res = spawnSync(
    "npm",
    [
      "install",
      "--no-save",
      "--no-audit",
      "--no-fund",
      "--prefix",
      installDir,
      `@forestrie/forestrie-cli@${version}`,
    ],
    { encoding: "utf8", timeout: 300_000 },
  );
  if (res.status !== 0) {
    throw new Error(
      `npm install of @forestrie/forestrie-cli@${version} failed: ${(
        res.stderr ||
        res.error?.message ||
        "npm install failed"
      )
        .trim()
        .slice(0, 800)}`,
    );
  }
  if (!existsSync(entry)) {
    throw new Error(
      `npm install of @forestrie/forestrie-cli@${version} succeeded but ${entry} is missing — has the package's bin layout changed?`,
    );
  }
  return entry;
}
