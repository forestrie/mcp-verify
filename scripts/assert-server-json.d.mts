/**
 * Hand-written declarations for `assert-server-json.mjs`, so
 * `test/node/*.test.ts` can import it under `strict` without an
 * implicit-any module error. `scripts/` is excluded from
 * `tsconfig.build.json` (this script ships as plain JS, unbuilt) but is
 * still typechecked via `test/**` importing it — keep this file in sync
 * with the exports below by hand, the same convention as
 * `self-register.d.mts`.
 */

export declare function checkServerJson(
  pkg: Record<string, unknown>,
  server: Record<string, unknown>,
): string[];
