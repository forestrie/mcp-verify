/**
 * Browser-safety guard (copied from
 * canopy/packages/libs/receipt-verify/tools/check-browser-safe.mjs, itself
 * written for ADR-0048): bundle the package entry for the
 * browser platform and fail if any node builtin is in the module graph.
 *
 * What this copy proves that the upstream one does not: not only that
 * `src/core` has no node edge, but that the MCP adapter's node dependencies
 * — `@modelcontextprotocol/sdk`, `node:fs`, `StdioServerTransport` — cannot
 * leak backwards into it. `src/core` is the `"."` export; an importer who
 * takes it gets none of `src/node`, and this is the check that says so.
 *
 * esbuild with `platform: "browser"` already errors on unresolvable
 * `node:*` specifiers; the metafile scan below also catches bare builtin
 * names (e.g. "crypto") that a future config change might externalize.
 * Both halves matter — do not simplify to one.
 *
 * If this gate ever goes red without `src/core` changing, look in
 * @forestrie/merklelog first: it holds the one `node:crypto` reference in the
 * graph, hidden behind an opaque string specifier so bundlers cannot resolve
 * it. Our gate inherits
 * that property. A merklelog release that makes the specifier resolvable
 * turns this red for a reason that lives in someone else's repo.
 */
import { build } from "esbuild";
import { builtinModules } from "node:module";
import { fileURLToPath } from "node:url";

const entry = fileURLToPath(new URL("../src/core/index.ts", import.meta.url));

const builtins = new Set([
  ...builtinModules,
  ...builtinModules.map((m) => `node:${m}`),
]);

let result;
try {
  result = await build({
    entryPoints: [entry],
    bundle: true,
    platform: "browser",
    format: "esm",
    write: false,
    metafile: true,
    logLevel: "silent",
  });
} catch (err) {
  console.error(
    "browser-safety check FAILED: @forestrie/mcp-verify (src/core) does not bundle for the browser platform.",
  );
  for (const e of err.errors ?? []) {
    console.error(
      `  ${e.text}${e.location ? ` (${e.location.file}:${e.location.line})` : ""}`,
    );
  }
  process.exit(1);
}

// A builtin can only appear in the metafile as an external import edge
// (an unresolvable one already failed the build above).
const offenders = [];
for (const [input, meta] of Object.entries(result.metafile.inputs)) {
  for (const imp of meta.imports ?? []) {
    if (builtins.has(imp.path)) {
      offenders.push(`${input} -> ${imp.path}`);
    }
  }
}

if (offenders.length > 0) {
  console.error(
    "browser-safety check FAILED: node builtins in @forestrie/mcp-verify (src/core)'s module graph:",
  );
  for (const o of offenders) console.error(`  ${o}`);
  process.exit(1);
}

console.log(
  "browser-safety check passed: @forestrie/mcp-verify (src/core) bundles for platform=browser with no node builtins.",
);
