/**
 * Version strings, as literals.
 *
 * Not read from `package.json`: `src/core` is browser-safe, so it has no
 * `node:fs`, and a JSON import would bake a resolveJsonModule edge into the
 * `"."` bundle for two strings. The MCP smoke test asserts
 * `PACKAGE_VERSION === package.json#version`, so a forgotten bump is a red
 * test rather than a silent lie in `initialize`'s serverInfo.
 *
 * Bump both in the same commit as the dependency they name.
 */

/** Keep in sync with package.json#version. Asserted by test/node/mcp-smoke. */
export const PACKAGE_VERSION = "0.6.0";

/** Keep in sync with package.json#dependencies["@forestrie/receipt-verify"].
 *  Asserted by test/core/verify-grant-receipt.test.ts. */
export const RECEIPT_VERIFY_VERSION = "3.1.0";

/** Keep in sync with package.json#dependencies["@forestrie/encoding"]. */
export const ENCODING_VERSION = "0.9.1";
