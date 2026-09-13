/**
 * Hand-written declarations for `forestrie-cli-npm.mjs`, so
 * `test/differential/cli-binary.ts` can import it under `strict` without an
 * implicit-any module error. `scripts/` is excluded from
 * `tsconfig.build.json` (this module ships as plain JS, unbuilt) but is
 * still typechecked via `test/**` importing it — keep this file in sync with
 * the exports below by hand, the same convention as `self-register.d.mts`.
 */

export declare const FORESTRIE_CLI_VERSION: string;

export declare function cliCacheDir(
  repoRoot: string,
  version?: string,
): string;

export declare function cliEntryPath(
  repoRoot: string,
  version?: string,
): string;

export declare function ensureForestrieCliInstalled(
  repoRoot: string,
  opts?: { version?: string; log?: (message: string) => void },
): string;
