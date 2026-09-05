/**
 * The reference client, pinned by checksum.
 *
 * `forestrie-cli` is `private: true` on npm and ships as compiled static
 * binaries on GitHub Releases, each with a `.sha256` sidecar. So the
 * differential test consumes a PUBLISHED RELEASE BINARY rather than a source
 * checkout, which is a deliberate deviation from the parent plan's wording
 * ("run via Bun in CI"):
 *
 * 1. It removes Bun from this repo entirely, CI included. The toolchain is
 *    mise node + pnpm and nothing else.
 * 2. A sha256 sidecar is a stronger pin than a git tag, which can be moved.
 * 3. It is literally what an outside auditor would run — the neutrality
 *    property the whole plan is about.
 * 4. A source checkout would need `bun install` against `receipt-verify
 *    ^0.9.0`, the very skew the differential exists to expose, and pinning a
 *    lockfile for someone else's repo is not maintainable.
 *
 * The cost: the pin tracks RELEASED behaviour, not an arbitrary commit. That
 * is a feature — released behaviour is what an outsider can reproduce.
 *
 * Rebase procedure: docs/differential-test.md.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { arch, platform } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** Bump deliberately; see docs/differential-test.md. */
export const CLI_TAG = "v0.7.0";

/**
 * Verified 2026-09-05 against the release's `.sha256` sidecars AND GitHub's
 * own asset digests — two independent witnesses for the same bytes.
 */
export const CLI_SHA256: Readonly<Record<string, string>> = {
  "linux-x64":
    "f211de74dc7944fb15ab652efddd0a9d6517239adea9c98cb0dd20484eccc1ed",
  "darwin-arm64":
    "a0b68282b39e491382051e2d496e677e35fd5ff814888a5fbf101d27bd0d175b",
};

const ASSET_NAMES: Readonly<Record<string, string>> = {
  "linux-x64": "forestrie-linux-x64",
  "darwin-arm64": "forestrie-darwin-arm64",
};

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

export function currentTarget(): string | null {
  const p = platform();
  const a = arch();
  if (p === "linux" && a === "x64") return "linux-x64";
  if (p === "darwin" && a === "arm64") return "darwin-arm64";
  // No release asset for this host (linux-arm64, darwin-x64, win32). The
  // differential is a cross-check, not a correctness gate on every developer's
  // laptop — CI runs the targets that exist.
  return null;
}

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

export type ResolveOutcome =
  | { bin: string; source: "env" | "cache" | "download" }
  | { bin: null; reason: string };

/**
 * Resolve the pinned reference binary:
 *   1. `$FORESTRIE_CLI_BIN`, if set (local override / air-gapped runs)
 *   2. a cached copy under `node_modules/.cache/forestrie-cli/<tag>/`
 *   3. download from the GitHub release, verify sha256, cache, chmod +x
 *
 * Returns `{bin: null, reason}` when unavailable, so the caller can skip with
 * a legible one-line reason instead of a mystery.
 */
export async function resolveCliBinary(): Promise<ResolveOutcome> {
  const override = process.env["FORESTRIE_CLI_BIN"];
  if (override !== undefined && override !== "") {
    if (!existsSync(override)) {
      return {
        bin: null,
        reason: `FORESTRIE_CLI_BIN='${override}' not found`,
      };
    }
    // Deliberately NOT checksum-checked: an override is an explicit local
    // decision to test against something else, and silently refusing it would
    // make bisecting a divergence impossible.
    return { bin: override, source: "env" };
  }

  const target = currentTarget();
  if (target === null) {
    return {
      bin: null,
      reason: `no forestrie ${CLI_TAG} release asset for ${platform()}-${arch()} (assets exist for linux-x64 and darwin-arm64)`,
    };
  }
  const expected = CLI_SHA256[target];
  const asset = ASSET_NAMES[target];
  if (expected === undefined || asset === undefined) {
    return { bin: null, reason: `no pinned digest for target '${target}'` };
  }

  const cacheDir = join(
    repoRoot,
    "node_modules",
    ".cache",
    "forestrie-cli",
    CLI_TAG,
  );
  const cached = join(cacheDir, asset);

  if (existsSync(cached)) {
    const actual = sha256File(cached);
    if (actual === expected) {
      chmodSync(cached, 0o755);
      return { bin: cached, source: "cache" };
    }
    // A corrupt cache must not become a silent re-download loop or, worse, a
    // differential run against unpinned bytes.
    return {
      bin: null,
      reason: `cached ${asset} has sha256 ${actual}, expected ${expected}; delete ${cacheDir} and retry`,
    };
  }

  const url = `https://github.com/forestrie/forestrie-cli/releases/download/${CLI_TAG}/${asset}`;
  mkdirSync(cacheDir, { recursive: true });
  const tmp = `${cached}.part`;

  // curl rather than fetch: this file runs in the `differential` vitest
  // project, which is not fetch-gated, but the binary is ~60-100 MB and
  // streaming it through a Response body buffer is a needless 100 MB of heap.
  const res = spawnSync(
    "curl",
    ["-sSfL", "--retry", "3", "--max-time", "600", "-o", tmp, url],
    { encoding: "utf8" },
  );
  if (res.status !== 0) {
    return {
      bin: null,
      reason: `could not download ${url}: ${(res.stderr || res.error?.message || "curl failed").trim()}`,
    };
  }

  const actual = sha256File(tmp);
  if (actual !== expected) {
    // Do NOT keep bytes that failed the pin. A differential test run against
    // unverified bytes proves nothing and would be worse than not running.
    writeFileSync(`${tmp}.rejected-digest`, `${actual}\n`);
    return {
      bin: null,
      reason: `downloaded ${asset} has sha256 ${actual}, expected ${expected} — refusing to use it`,
    };
  }
  renameSync(tmp, cached);
  chmodSync(cached, 0o755);
  return { bin: cached, source: "download" };
}

export type CliRun = { status: number; stdout: string; stderr: string };

/** Run the reference CLI. Never throws: a crash is data the test wants. */
export function runCli(bin: string, args: string[]): CliRun {
  const res = spawnSync(bin, args, { encoding: "utf8", timeout: 60_000 });
  return {
    status: res.status ?? -1,
    stdout: res.stdout ?? "",
    stderr: res.stderr ?? "",
  };
}
