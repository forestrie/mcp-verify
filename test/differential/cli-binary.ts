/**
 * The reference client, pinned by npm version.
 *
 * `@forestrie/forestrie-cli` publishes to npm from 0.8.0 (plan-2609-02
 * workstream P, step P5), Node-runnable with `bin: { forestrie: "dist/cli.js" }`.
 * That replaces the earlier sha256-pinned GitHub-release binary this file
 * used to resolve:
 *
 * 1. It removes the per-host release-asset matrix entirely. There was no
 *    `linux-arm64`, `darwin-x64` or Windows asset for the Bun binary, so
 *    those hosts skipped the differential test; an npm package runs
 *    identically everywhere `node` does.
 * 2. It is literally what an outside auditor runs (`npx -y
 *    @forestrie/forestrie-cli`) — the neutrality property the whole plan is
 *    about — and it is now on the same `@forestrie/receipt-verify` (1.0.0)
 *    and `@forestrie/encoding` (0.7.0) as this package, so the version-skew
 *    triage row this file's docs used to carry no longer applies.
 * 3. A checksum sidecar is no longer available (npm packages are not
 *    sha256-sidecarred the way GitHub release assets are), so the pin is now
 *    the exact, deliberately-bumped `FORESTRIE_CLI_VERSION` below, resolved
 *    through npm's own registry-integrity check on install.
 *
 * ## How the version is resolved
 *
 * `npm install --no-save --prefix <cache dir>
 * @forestrie/forestrie-cli@<FORESTRIE_CLI_VERSION>`, once per pinned version,
 * into a directory under the gitignored `node_modules/.cache/` — mirroring
 * the old binary cache's shape (keyed by pin, reused across runs, a bump
 * invalidates it by construction). `--no-save --prefix` means this NEVER
 * touches this repo's own `package.json` or pnpm lockfile: `@forestrie/
 * forestrie-cli` is not, and must not become, a dependency of this package
 * for the differential test alone (see docs/differential-test.md). The
 * install-and-cache mechanics live in `scripts/forestrie-cli-npm.mjs`,
 * shared with `scripts/self-register.mjs` — one pinned version, one cache
 * layout, not two.
 *
 * The installed `dist/cli.js` is then run as `node <entry> <args>` — under
 * the SAME node binary running the test, not execed directly — so this works
 * identically on linux, darwin and Windows. There is no per-platform skip any
 * more.
 *
 * Rebase procedure: docs/differential-test.md.
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  FORESTRIE_CLI_VERSION,
  cliEntryPath,
  ensureForestrieCliInstalled,
} from "../../scripts/forestrie-cli-npm.mjs";

export { FORESTRIE_CLI_VERSION };

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const cliEntry = cliEntryPath(repoRoot, FORESTRIE_CLI_VERSION);

export type CliRun = { status: number; stdout: string; stderr: string };

export type ResolveOutcome =
  | { run: (args: string[]) => CliRun; source: "env" | "npm-install" }
  | { run: null; reason: string };

function spawnViaNode(entry: string, args: string[]): CliRun {
  const res = spawnSync(process.execPath, [entry, ...args], {
    encoding: "utf8",
    timeout: 60_000,
  });
  return {
    status: res.status ?? -1,
    stdout: res.stdout ?? "",
    stderr: res.stderr ?? "",
  };
}

/** Never throws: a crash is data the test wants. */
function spawnDirect(bin: string, args: string[]): CliRun {
  const res = spawnSync(bin, args, { encoding: "utf8", timeout: 60_000 });
  return {
    status: res.status ?? -1,
    stdout: res.stdout ?? "",
    stderr: res.stderr ?? "",
  };
}

/**
 * Resolve the reference client:
 *
 *   1. `$FORESTRIE_CLI_BIN`, if set. Deliberately **not** version-checked: an
 *      override is an explicit local decision to test against something
 *      else (a locally built binary, a dev checkout's compiled entry point,
 *      …), and silently refusing it would make bisecting a divergence
 *      impossible. Run directly, exactly as before this file switched to
 *      npm. The test warns when it is in use.
 *   2. `npm install --no-save` of the pinned `FORESTRIE_CLI_VERSION` into a
 *      cached scratch prefix, then `node <installed dist/cli.js>`.
 *
 * Returns `{run: null, reason}` when unavailable, so the caller can skip with
 * a legible one-line reason instead of a mystery.
 */
export async function resolveCliBinary(): Promise<ResolveOutcome> {
  const override = process.env["FORESTRIE_CLI_BIN"];
  if (override !== undefined && override !== "") {
    if (!existsSync(override)) {
      return {
        run: null,
        reason: `FORESTRIE_CLI_BIN='${override}' not found`,
      };
    }
    return { run: (args) => spawnDirect(override, args), source: "env" };
  }

  if (!existsSync(cliEntry)) {
    try {
      // No lockfile involved: this is a scratch `--prefix`, resolved fresh
      // against the public registry. `--no-save` is what keeps it from ever
      // touching this repo's own package.json.
      ensureForestrieCliInstalled(repoRoot, {
        version: FORESTRIE_CLI_VERSION,
      });
    } catch (err) {
      return {
        run: null,
        reason: err instanceof Error ? err.message : String(err),
      };
    }
  }

  return {
    run: (args) => spawnViaNode(cliEntry, args),
    source: "npm-install",
  };
}
