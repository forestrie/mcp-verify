/**
 * `verify --self` — the CLI narration for `verifySelf`, over `fixtures/self/`
 * (plan-2609-02 step 2.5). Same shape as `demo.ts`: everything printed goes
 * through the caller's writer, never `console`, so `cli.ts` can guarantee
 * stdio mode writes nothing to stdout but MCP frames.
 *
 * Exit codes: `0` PASS, `1` FAIL, `2` the bundle is absent — a checkout that
 * is not itself the published tarball, which is the normal state for most
 * clones and is not an error in itself, just not something this command can
 * run against.
 */
import { summarizeSelf, verifySelf } from "../core/index.js";
import { loadSelfBundle } from "./fixtures.js";

export type Writer = (line: string) => void;

const BUNDLE_ABSENT_MESSAGE =
  "this checkout was not produced by a release; run the release rehearsal " +
  "or use a published tarball";

export async function runVerifySelf(write: Writer): Promise<number> {
  const bundle = loadSelfBundle();
  if (bundle === null) {
    write(`forestrie-mcp-verify: ${BUNDLE_ABSENT_MESSAGE}`);
    return 2;
  }

  const result = await verifySelf(bundle);

  write("");
  write("@forestrie/mcp-verify — verify --self");
  write("");
  write("Verifying this package's own release-time self-registration receipt");
  write("against the bundled log owner key. No network, no account.");
  write("");
  write(`  ${summarizeSelf(result)}`);
  for (const row of result.stages) {
    write(
      `    ${row.stage.padEnd(10)} ${row.status.padEnd(8)}${
        row.reason !== undefined ? ` — ${row.reason}` : ""
      }`,
    );
  }
  write("");
  for (const q of [
    "sealing",
    "split-view",
    "append-authority",
    "attribution",
  ] as const) {
    const a = result.questions[q];
    write(`    ${q.padEnd(17)} ${a.status.padEnd(24)} ${a.note}`);
  }
  write("");
  for (const d of result.diagnostics) {
    write(`    ! ${d.code}`);
    write(`      ${d.message}`);
  }
  write("");
  write("docs/self-registration.md has the full account of what this");
  write("bundle is and why known-log-key, not genesis, is the default root.");
  write("");

  return result.ok ? 0 : 1;
}
