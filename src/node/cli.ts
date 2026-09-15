/**
 * The bin entry, reached via `bin/mcp-verify.mjs`.
 *
 *   <no args>          → StdioServerTransport; this is what
 *                        `npx -y @forestrie/mcp-verify` does.
 *   demo               → run two trust roots over the bundled fixtures.
 *   verify --self      → verify this package's own release-time
 *                        self-registration receipt against the bundled log
 *                        owner key. Exit 2, not 1,
 *                        when `fixtures/self/` is absent — the normal state
 *                        for a checkout that is not itself the published
 *                        tarball, not a verification failure.
 *   --help | --version → text on stdout, exit 0.
 *
 * TWO RULES, both silent-corruption bugs if broken:
 *
 * 1. **Nothing may write to stdout in stdio mode except the transport.** A
 *    stray `console.log` does not produce a warning — it produces a malformed
 *    JSON-RPC frame and an MCP client that mysteriously fails to initialise.
 *    All logging goes to stderr. `scripts/check-stdio-clean.mjs` proves it
 *    against a real spawned process on every CI run.
 *
 * 2. **`main` returns an exit code; it does not call `process.exit`.** Killing
 *    the process mid-write truncates whatever the stdio transport had
 *    buffered. The wrapper sets `process.exitCode` and lets node drain.
 *
 * No `citty`. The CLI camp reaches it through `@forestrie/cli-kit`, but that
 * is another `@forestrie/*` package to pin, another node_modules subtree for
 * the encoding-copy gate to walk, and this bin has three verbs.
 */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { PACKAGE_VERSION, RECEIPT_VERIFY_VERSION } from "../core/index.js";
import { runDemo } from "./demo.js";
import { runVerifySelf } from "./self-cli.js";
import { createServer } from "./server.js";

const HELP = `forestrie-mcp-verify ${PACKAGE_VERSION}

  MCP verification server for Forestrie receipts.
  Offline: no backend, no account, no key, no network.

USAGE
  forestrie-mcp-verify                start the MCP server on stdio (the default)
  forestrie-mcp-verify demo           run two trust roots over the bundled fixtures
  forestrie-mcp-verify verify --self  verify this package's own release
                                       registration against the bundled log key
  forestrie-mcp-verify --help
  forestrie-mcp-verify --version

TOOLS
  verify_receipt         payload receipt + exact payload + entry id + trust root
  verify_grant_receipt   grant receipt + committed grant + trust root
  verify_self            this package's own release-time self-registration
  decode_receipt         CBOR to JSON. No verification.

TRUST ROOTS (the "root" field)
  genesis             the log's genesis document
  known-log-key       a log owner key you hold out of band
  known-accumulator   an on-chain accumulator snapshot you hold
  checkpoint-chain    a retained .sth chain you hold

  The root decides which of the four trust questions can be answered.
  Only known-accumulator and checkpoint-chain answer split-view. The tool
  always says which. Which root is right depends on what you hold and
  what you need to know.

CLIENT CONFIG
  {"mcpServers": {"forestrie-verify":
    {"command": "npx", "args": ["-y", "@forestrie/mcp-verify"]}}}

  Verifier: @forestrie/receipt-verify ${RECEIPT_VERIFY_VERSION}
  Docs:     https://github.com/forestrie/mcp-verify#readme
`;

/** stdout is the transport in stdio mode; everything else is stderr. */
const out = (line: string): void => {
  process.stdout.write(`${line}\n`);
};

export async function main(argv: readonly string[]): Promise<number> {
  const args = [...argv];

  if (args.includes("--help") || args.includes("-h") || args[0] === "help") {
    out(HELP);
    return 0;
  }
  if (args.includes("--version") || args.includes("-v")) {
    out(PACKAGE_VERSION);
    return 0;
  }

  const verb = args[0];

  if (verb === "demo") {
    return runDemo(out);
  }

  if (verb === "verify") {
    if (args.includes("--self")) {
      return runVerifySelf(out);
    }
    process.stderr.write(
      "forestrie-mcp-verify: `verify` currently supports only --self. " +
        "To verify a receipt now, call the verify_receipt or " +
        "verify_grant_receipt MCP tool, or run `demo`.\n",
    );
    return 1;
  }

  if (verb !== undefined && !verb.startsWith("-")) {
    process.stderr.write(
      `forestrie-mcp-verify: unknown command '${verb}'. Try --help.\n`,
    );
    return 1;
  }

  // Default: speak MCP on stdio. From here on, stdout belongs to the
  // transport and nothing else may touch it.
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Resolve when the transport closes, so the wrapper can set an exit code
  // rather than the process being torn down mid-write.
  await new Promise<void>((resolve) => {
    transport.onclose = () => resolve();
    process.on("SIGINT", () => resolve());
    process.on("SIGTERM", () => resolve());
  });
  return 0;
}

/**
 * Entry point. `process.exitCode` rather than `process.exit()`: node then
 * drains stdout before exiting, which a hard exit would not.
 */
export async function run(): Promise<void> {
  try {
    process.exitCode = await main(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(
      `forestrie-mcp-verify: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`,
    );
    process.exitCode = 1;
  }
}

await run();
