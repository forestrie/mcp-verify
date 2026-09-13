/**
 * Shared npm-install resolution for the reference `@forestrie/forestrie-cli`.
 *
 * Two consumers need "the pinned reference CLI, resolved from npm, run under
 * plain `node`": `scripts/self-register.mjs` (release-time
 * delegate/sign-statement/register) and `test/differential/cli-binary.ts`
 * (the differential test's reference client). Before this file, each had its
 * own copy of the install-and-cache logic; `self-register.mjs` additionally
 * carried a now-removed sha256-pinned GitHub-release binary downloader. One
 * pinned version and one cache layout here means a version bump is a single
 * edit, not two — the same "no duplicate source of truth" discipline
 * AGENTS.md asks of `@forestrie/*` dependency pins generally.
 *
 * `--no-save --prefix` never touches this repo's own `package.json` or pnpm
 * lockfile: `@forestrie/forestrie-cli` is not, and must not become, a
 * dependency of this package. See docs/differential-test.md for why npm and
 * not a source checkout or a downloaded binary.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";

/** Bump deliberately; see docs/differential-test.md. */
export const FORESTRIE_CLI_VERSION = "0.8.1";

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
