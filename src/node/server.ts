/**
 * `createServer()` — the three phase-1 tools and the fixture resources wired
 * onto a fresh `McpServer`. No transport: the caller connects one (stdio from
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
 * transcript, and it must never be a bare "valid" — it names the rung and
 * which questions went unanswered (D3).
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  DecodeReceiptError,
  PACKAGE_VERSION,
  decodeReceipt,
  summarize,
  verifyGrantReceipt,
  verifyReceipt,
  type VerifyResult,
} from "../core/index.js";
import { InputError, resolveBytes, resolveRung } from "./resolve-input.js";
import type { BytesInput, TrustRungInput } from "./resolve-input.js";
import {
  decodeOutputShape,
  decodeReceiptInputShape,
  verifyGrantReceiptInputShape,
  verifyOutputShape,
  verifyReceiptInputShape,
} from "./tools.js";
import { BURIAL_MANIFEST, readFixture, readFixtureText } from "./fixtures.js";

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

export function createServer(): McpServer {
  const server = new McpServer(
    { name: SERVER_NAME, version: PACKAGE_VERSION },
    {
      instructions:
        "Offline Forestrie receipt verification. Every tool is pure over " +
        "bytes: no network, no account, no key, no backend. Choose a trust " +
        "rung deliberately — the answer tells you which of the four trust " +
        "questions that rung can answer, and 'not_answered_at_this_rung' is " +
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
        "bytes and an entry id, at a trust rung you choose. Mirrors " +
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
          trust: resolveRung(args.trust as TrustRungInput),
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
        "entry id), at a trust rung you choose. Mirrors " +
        "`forestrie verify-grant`. This is the tool that answers the " +
        "authority question: the leaf IS the grant.",
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
          trust: resolveRung(args.trust as TrustRungInput),
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

  registerFixtureResources(server);
  return server;
}

/**
 * The bundled golden vectors as MCP resources, so an agent can run the demo
 * with no inputs of its own (D2). The `forestrie://self/…` namespace is
 * reserved for phase 2's self-registration artefacts and is deliberately NOT
 * registered here — an empty namespace is better than one that resolves to
 * nothing.
 */
function registerFixtureResources(server: McpServer): void {
  const binaryFixtures: { rel: string; title: string; description: string }[] =
    [
      {
        rel: "golden/grant-genesis.cbor",
        title: "Golden genesis document",
        description:
          "The forest-genesis document for the golden log. The genesis rung's trust root.",
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
          "One link of the retained .sth chain the checkpoint-chain rung folds.",
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
