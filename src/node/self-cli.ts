/**
 * `verify --self` — the CLI narration for `verifySelf`, over `fixtures/self/`.
 * Same shape as `demo.ts`: everything printed goes
 * through the caller's writer, never `console`, so `cli.ts` can guarantee
 * stdio mode writes nothing to stdout but MCP frames.
 *
 * Exit codes: `0` PASS, `1` FAIL, `2` the bundle is absent — a checkout that
 * is not itself the published tarball, which is the normal state for most
 * clones and is not an error in itself, just not something this command can
 * run against.
 */
import { summarizeSelf, verifySelf, type TrustRoot } from "../core/index.js";
import { loadSelfBundle } from "./fixtures.js";

export type Writer = (line: string) => void;

const BUNDLE_ABSENT_MESSAGE =
  "this checkout was not produced by a release; run the release rehearsal " +
  "or use a published tarball";

/** The roots `verify --self --root <name>` can run without bytes from the
 *  caller: both come from the bundle. `known-accumulator` needs a snapshot
 *  the bundle does not ship, so it is the `verify_self` MCP tool's job
 *  (`root.accumulator`), and the CLI says so rather than ignoring the flag. */
export const SELF_CLI_ROOTS = ["known-log-key", "genesis"] as const;
export type SelfCliRoot = (typeof SELF_CLI_ROOTS)[number];

export type RunVerifySelfOptions = {
  /** Defaults to `known-log-key`, as the tool does. */
  root?: SelfCliRoot;
};

/** Exit 1 with this line when `--root` names something the CLI cannot run. */
export function unsupportedSelfRootMessage(root: string): string {
  return (
    `forestrie-mcp-verify: verify --self --root ${root} is not supported; ` +
    `--root takes ${SELF_CLI_ROOTS.join(" or ")}. ` +
    "A known-accumulator run needs a snapshot the bundle does not ship: " +
    "call the verify_self MCP tool with root.accumulator instead."
  );
}

/** `--root <name>` out of `verify --self`'s argv: absent is the default
 *  root; a value outside `SELF_CLI_ROOTS`, or a missing value, is a
 *  one-line refusal for stderr and exit 1 — never silently ignored, which
 *  is what `verify --self --root genesis` used to do. Pure, so the test
 *  can drive it without importing `cli.ts` (whose module body starts the
 *  stdio server). */
export function parseSelfRootFlag(
  args: readonly string[],
):
  | { ok: true; root: SelfCliRoot | undefined }
  | { ok: false; message: string } {
  const at = args.indexOf("--root");
  if (at === -1) return { ok: true, root: undefined };
  const value = args[at + 1];
  if (value === undefined || value.startsWith("-")) {
    return {
      ok: false,
      message: `forestrie-mcp-verify: --root needs a value: ${SELF_CLI_ROOTS.join(" or ")}.`,
    };
  }
  if (!(SELF_CLI_ROOTS as readonly string[]).includes(value)) {
    return { ok: false, message: unsupportedSelfRootMessage(value) };
  }
  return { ok: true, root: value as SelfCliRoot };
}

export async function runVerifySelf(
  write: Writer,
  options: RunVerifySelfOptions = {},
): Promise<number> {
  const bundle = loadSelfBundle();
  if (bundle === null) {
    write(`forestrie-mcp-verify: ${BUNDLE_ABSENT_MESSAGE}`);
    return 2;
  }

  const rootName: SelfCliRoot = options.root ?? "known-log-key";
  const root: TrustRoot =
    rootName === "genesis"
      ? { root: "genesis", genesis: bundle.genesis }
      : { root: "known-log-key", keyXy: bundle.logKeyXy };
  const result = await verifySelf(bundle, { root });

  write("");
  write(`@forestrie/mcp-verify — verify --self --root ${rootName}`);
  write("");
  write("Verifying this package's own release-time self-registration receipt");
  if (rootName === "genesis") {
    write(
      "against the bundled forest genesis document. No network, no account.",
    );
    write("");
    write(
      "Expect delegation_invalid: the genesis root's offline walk resolves one",
    );
    write(
      "delegation hop from the forest root, and the publications log this",
    );
    write("receipt is from is a grandchild. That is the walk's limit, not a");
    write("finding about the receipt — docs/self-registration.md.");
  } else {
    write("against the bundled log owner key. No network, no account.");
  }
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
