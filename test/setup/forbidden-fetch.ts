import { afterAll, beforeAll } from "vitest";

/**
 * The verify path is pure over bytes. Any fetch under any tool
 * call is a bug, not a slow test — so the whole unit project runs with a
 * fetch that throws, rather than forestrie-cli's per-call swap
 * (forestrie-cli/test/verify.test.ts:67-70).
 *
 * The message names the invariant, not the symptom: a stack trace ending
 * here is telling you that src/core or src/node reached the network.
 *
 * Scope note: fetch only, deliberately. Blocking node:net's
 * Socket.prototype.connect would be the strong version, but it fires on
 * vitest's own worker IPC. The esbuild gate already proves src/core has no
 * path to node:net at all, which is the stronger statement for the layer
 * that matters.
 */
const realFetch = globalThis.fetch;

const forbiddenFetch = ((input: unknown) => {
  throw new Error(
    `network forbidden: @forestrie/mcp-verify verifies offline, but something fetched ${String(input)}`,
  );
}) as unknown as typeof fetch;

beforeAll(() => {
  globalThis.fetch = forbiddenFetch;
  // "No fetch" is not the whole of "no network"; XHR is harmless to remove
  // in node and closes the other obvious door.
  (globalThis as { XMLHttpRequest?: unknown }).XMLHttpRequest = undefined;
});

afterAll(() => {
  globalThis.fetch = realFetch;
});
