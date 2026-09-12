/**
 * `createServer()` — the four tools and the fixture resources wired onto a
 * fresh `McpServer`. No transport: the caller connects one (stdio from
 * `cli.ts`, `InMemoryTransport` from the smoke test), which is also what lets
 * an embedder mount these tools on their own transport without the CLI.
 *
 * Every tool is annotated `readOnlyHint: true, openWorldHint: false`. That is
 * not decoration: it is the machine-readable form of "this tool touches
 * nothing", which is the entire pitch. An agent that reads annotations should
 * be able to see, without running anything, that installing this server
 * cannot cause a network call.
 *
 * Every handler returns BOTH `structuredContent` (the full result) and a
 * one-line `content[0].text` summary. The summary is what a human reads in the
 * transcript, and it must never be a bare "valid" — it names the root and
 * which questions went unanswered (D3).
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  DecodeReceiptError,
  PACKAGE_VERSION,
  decodeReceipt,
  summarize,
  summarizeSelf,
  verifyGrantReceipt,
  verifyReceipt,
  verifySelf,
  type SelfVerifyResult,
  type TrustRoot,
  type VerifyResult,
} from "../core/index.js";
import { InputError, resolveBytes, resolveRoot } from "./resolve-input.js";
import type { BytesInput, TrustRootInput } from "./resolve-input.js";
import {
  decodeOutputShape,
  decodeReceiptInputShape,
  verifyGrantReceiptInputShape,
  verifyOutputShape,
  verifyReceiptInputShape,
  verifySelfInputShape,
  verifySelfOutputShape,
} from "./tools.js";
import {
  BURIAL_MANIFEST,
  listSelfFixtures,
  loadSelfBundle,
  readFixture,
  readFixtureText,
  readSelfFixture,
} from "./fixtures.js";

const SERVER_NAME = "forestrie-mcp-verify";

type ToolResult = {
  content: { type: "text"; text: string }[];
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
};

/**
 * An input error is a TOOL error, not a verification failure, and the two
 * must never be confused: "I could not read your file" is not "your receipt
 * is invalid". `isError: true` with no `structuredContent` says so.
 */
function inputError(err: unknown): ToolResult {
  const message = err instanceof Error ? err.message : String(err);
  return {
    isError: true,
    content: [{ type: "text", text: `input error: ${message}` }],
  };
}

function verifyResult(verb: string, result: VerifyResult): ToolResult {
  return {
    structuredContent: result as unknown as Record<string, unknown>,
    content: [{ type: "text", text: summarize(verb, result) }],
  };
}

function verifySelfResult(result: SelfVerifyResult): ToolResult {
  return {
    structuredContent: result as unknown as Record<string, unknown>,
    content: [{ type: "text", text: summarizeSelf(result) }],
  };
}

/**
 * `verify_self`'s wire-form root — narrower than `TrustRootInput`, because
 * the `known-log-key` and `genesis` bytes come from the bundle itself. Only
 * `known-accumulator` needs bytes from the caller.
 */
type SelfRootInput =
  | { root: "known-log-key" }
  | { root: "genesis" }
  | {
      root: "known-accumulator";
      accumulator: BytesInput;
      massif?: BytesInput;
      consistencyProof?: BytesInput;
    };

function resolveSelfRoot(
  bundle: { logKeyXy: Uint8Array; genesis: Uint8Array },
  input: SelfRootInput | undefined,
): TrustRoot {
  if (input === undefined || input.root === "known-log-key") {
    return { root: "known-log-key", keyXy: bundle.logKeyXy };
  }
  if (input.root === "genesis") {
    return { root: "genesis", genesis: bundle.genesis };
  }
  const out: TrustRoot = {
    root: "known-accumulator",
    accumulator: resolveBytes(input.accumulator, "root.accumulator"),
  };
  if (input.massif !== undefined) {
    out.massif = resolveBytes(input.massif, "root.massif");
  }
  if (input.consistencyProof !== undefined) {
    out.consistencyProof = resolveBytes(
      input.consistencyProof,
      "root.consistencyProof",
    );
  }
  return out;
}

/** `verify_self`'s clear, non-throwing error for a checkout with no
 *  `fixtures/self/` bundle — the normal state for anything that is not
 *  itself the published tarball. */
function selfBundleAbsent(): ToolResult {
  return {
    isError: true,
    content: [
      {
        type: "text",
        text:
          "this checkout was not produced by a release; run the release " +
          "rehearsal or use a published tarball",
      },
    ],
  };
}

export function createServer(): McpServer {
  const server = new McpServer(
    { name: SERVER_NAME, version: PACKAGE_VERSION },
    {
      instructions:
        "Offline Forestrie receipt verification. Every tool is pure over " +
        "bytes: no network, no account, no key, no backend. Choose a trust " +
        "root deliberately — the answer tells you which of the four trust " +
        "questions that root can answer, and 'not_answered_by_this_root' is " +
        "a real answer that must be shown to the user.",
    },
  );

  const annotations = {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  } as const;

  server.registerTool(
    "verify_receipt",
    {
      title: "Verify a payload receipt",
      description:
        "Verify a Forestrie receipt against the EXACT registered payload " +
        "bytes and an entry id, at a trust root you choose. Mirrors " +
        "`forestrie verify`. Offline: no network, no key, no account. " +
        "Returns both the mechanical stages and the four trust questions.",
      inputSchema: verifyReceiptInputShape,
      outputSchema: verifyOutputShape,
      annotations,
    },
    async (args) => {
      try {
        const result = await verifyReceipt({
          receipt: resolveBytes(args.receipt as BytesInput, "receipt"),
          payload: resolveBytes(args.payload as BytesInput, "payload"),
          entryId: args.entryId,
          trust: resolveRoot(args.trust as TrustRootInput),
        });
        return verifyResult("verify", result);
      } catch (err) {
        if (err instanceof InputError) return inputError(err);
        throw err;
      }
    },
  );

  server.registerTool(
    "verify_grant_receipt",
    {
      title: "Verify a grant receipt",
      description:
        "Verify a Forestrie grant receipt against the committed grant " +
        "(Forestrie-Grant COSE Sign1, or raw grant payload CBOR plus an " +
        "entry id), at a trust root you choose. Mirrors " +
        "`forestrie verify-grant`. This is the tool that answers the " +
        "append-authority question: the leaf IS the grant.",
      inputSchema: verifyGrantReceiptInputShape,
      outputSchema: verifyOutputShape,
      annotations,
    },
    async (args) => {
      try {
        const result = await verifyGrantReceipt({
          receipt: resolveBytes(args.receipt as BytesInput, "receipt"),
          committedGrant: resolveBytes(
            args.committedGrant as BytesInput,
            "committedGrant",
          ),
          ...(args.entryId !== undefined ? { entryId: args.entryId } : {}),
          trust: resolveRoot(args.trust as TrustRootInput),
        });
        return verifyResult("verify-grant", result);
      } catch (err) {
        if (err instanceof InputError) return inputError(err);
        throw err;
      }
    },
  );

  server.registerTool(
    "decode_receipt",
    {
      title: "Decode a receipt to JSON",
      description:
        "Render a COSE receipt's CBOR as JSON — headers, named labels, " +
        "payload, signature and inclusion proof. NO VERIFICATION is " +
        "performed: a receipt that decodes cleanly may still be invalid. " +
        "Mirrors `forestrie decode-receipt --json`.",
      inputSchema: decodeReceiptInputShape,
      outputSchema: decodeOutputShape,
      annotations,
    },
    async (args) => {
      let bytes: Uint8Array;
      try {
        bytes = resolveBytes(args.receipt as BytesInput, "receipt");
      } catch (err) {
        if (err instanceof InputError) return inputError(err);
        throw err;
      }
      try {
        const decoded = decodeReceipt(bytes);
        return {
          structuredContent: decoded as unknown as Record<string, unknown>,
          content: [
            {
              type: "text",
              text:
                `decode: ${decoded.byteLength} B, alg=${
                  decoded.protected.alg?.name ?? "unknown"
                }, payload=${
                  decoded.payload.detached ? "detached" : "attached"
                }, inclusion path ${decoded.inclusion.pathLength} node(s) at ` +
                `mmrIndex ${decoded.inclusion.mmrIndex} — NOT verified`,
            },
          ],
        };
      } catch (err) {
        if (err instanceof DecodeReceiptError) {
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: `decode failed at stage=${err.stage}: ${err.message}`,
              },
            ],
          };
        }
        throw err;
      }
    },
  );

  server.registerTool(
    "verify_self",
    {
      title: "Verify this package's own release registration",
      description:
        "Verify this package's own release-time self-registration receipt: " +
        "does the receipt commit the signed statement, does that " +
        "statement's payload match the bundled provenance.json " +
        "byte-for-byte, and does its ES256 signature verify under the " +
        "bundled log owner key? No inputs required. Defaults to the " +
        "known-log-key root with the bundled key, not genesis — the " +
        "publications log is a grandchild of the forest root and nothing " +
        "walks that grant chain yet (docs/self-registration.md). Errors " +
        "clearly, rather than throwing, when this checkout has no " +
        "fixtures/self/ bundle (any checkout that is not itself the " +
        "published tarball).",
      inputSchema: verifySelfInputShape,
      outputSchema: verifySelfOutputShape,
      annotations,
    },
    async (args) => {
      const bundle = loadSelfBundle();
      if (bundle === null) return selfBundleAbsent();
      try {
        const root = resolveSelfRoot(
          bundle,
          args.root as SelfRootInput | undefined,
        );
        const result = await verifySelf(bundle, { root });
        return verifySelfResult(result);
      } catch (err) {
        if (err instanceof InputError) return inputError(err);
        throw err;
      }
    },
  );

  registerFixtureResources(server);
  registerSelfResources(server);
  return server;
}

/**
 * The bundled golden vectors as MCP resources, so an agent can run the demo
 * with no inputs of its own (D2). `registerSelfResources` below covers the
 * `forestrie://self/…` namespace, previously reserved but unregistered.
 */
function registerFixtureResources(server: McpServer): void {
  const binaryFixtures: { rel: string; title: string; description: string }[] =
    [
      {
        rel: "golden/grant-genesis.cbor",
        title: "Golden genesis document",
        description:
          "The forest-genesis document for the golden log — what the `genesis` root trusts.",
      },
      {
        rel: "golden/grant-receipt.cbor",
        title: "Golden grant receipt",
        description:
          "A 118-byte detached-payload grant receipt. The receipt the collapse table is about.",
      },
      {
        rel: "golden/burial/burial-receipt.cbor",
        title: "Burial-bundle receipt",
        description:
          "A receipt whose peak the log has since buried; re-anchored by the retained chain.",
      },
      ...BURIAL_MANIFEST.checkpointFiles.map((file) => ({
        rel: `golden/burial/${file}`,
        title: `Retained checkpoint ${file}`,
        description:
          "One link of the retained .sth chain the checkpoint-chain root folds.",
      })),
    ];

  for (const f of binaryFixtures) {
    const uri = `forestrie://fixtures/${f.rel}`;
    server.registerResource(
      f.rel,
      uri,
      {
        title: f.title,
        description: f.description,
        mimeType: "application/cbor",
      },
      async () => ({
        contents: [
          {
            uri,
            mimeType: "application/cbor",
            blob: Buffer.from(readFixture(f.rel)).toString("base64"),
          },
        ],
      }),
    );
  }

  for (const rel of ["golden/manifest.json", "golden/burial/manifest.json"]) {
    const uri = `forestrie://fixtures/${rel}`;
    server.registerResource(
      rel,
      uri,
      {
        title: `Fixture manifest (${rel})`,
        description:
          "Frozen-bytes manifest: the sha256 digests the pin test asserts, plus the " +
          "log id, grant data and idtimestamp the committed grant is rebuilt from.",
        mimeType: "application/json",
      },
      async () => ({
        contents: [
          { uri, mimeType: "application/json", text: readFixtureText(rel) },
        ],
      }),
    );
  }
}

/** Which `fixtures/self/` files are text vs binary, and their mime type —
 *  same six files `loadSelfBundle` requires (`fixtures.ts`), keyed here by
 *  name because a resource needs a mime type a `SelfBundle` field does not
 *  carry. */
const SELF_FIXTURE_KINDS: Record<string, { mimeType: string; text: boolean }> =
  {
    "provenance.json": { mimeType: "application/json", text: true },
    "statement.cose": { mimeType: "application/cbor", text: false },
    "receipt.cbor": { mimeType: "application/cbor", text: false },
    "genesis.cbor": { mimeType: "application/cbor", text: false },
    "log-key.xy.b64": { mimeType: "text/plain", text: true },
    "entry-id.txt": { mimeType: "text/plain", text: true },
    "manifest.json": { mimeType: "application/json", text: true },
  };

/**
 * `fixtures/self/` as `forestrie://self/…` MCP resources, when the bundle is
 * present — never when it is not (an unregistered namespace beats one that
 * resolves to nothing, `test/node/mcp-smoke.test.ts`). `fixtures/self/` is
 * generated and gitignored (plan-2609-02 step 2.3), so this is normally a
 * no-op outside a release checkout.
 */
function registerSelfResources(server: McpServer): void {
  for (const name of listSelfFixtures()) {
    const kind = SELF_FIXTURE_KINDS[name];
    if (kind === undefined) continue; // an unrecognised extra file, e.g. a dotfile an OS left behind
    const uri = `forestrie://self/${name}`;
    server.registerResource(
      `self/${name}`,
      uri,
      {
        title: `Self-registration bundle: ${name}`,
        description:
          "This package's own release-time self-registration artefact " +
          "(plan-2609-02 step 2.3) — what verify_self / verify --self " +
          "checks. See docs/self-registration.md.",
        mimeType: kind.mimeType,
      },
      async () =>
        kind.text
          ? {
              contents: [
                {
                  uri,
                  mimeType: kind.mimeType,
                  text: new TextDecoder().decode(readSelfFixture(name)),
                },
              ],
            }
          : {
              contents: [
                {
                  uri,
                  mimeType: kind.mimeType,
                  blob: Buffer.from(readSelfFixture(name)).toString("base64"),
                },
              ],
            },
    );
  }
}
