#!/usr/bin/env node
/**
 * The one thing InMemoryTransport cannot catch: a stray write to stdout
 * corrupting the JSON-RPC framing of a REAL process.
 *
 * Spawns the bin with no arguments (stdio mode), sends `initialize`, then
 * `notifications/initialized` and `tools/list`, keeps reading until a quiet
 * window (500 ms) has passed after the last response, and asserts that every
 * stdout line is a well-formed JSON-RPC message accounted for by what was
 * sent (a response to one of those ids, or a notification) and NOTHING ELSE.
 * A `console.log` anywhere in the server does not warn — it makes an MCP client fail to
 * initialise for no visible reason, and this is the only place that
 * failure is legible.
 *
 * Usage: node scripts/check-stdio-clean.mjs [pathToBin]
 *   default bin: ./bin/mcp-verify.mjs
 */
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const bin =
  process.argv[2] ??
  fileURLToPath(new URL("../bin/mcp-verify.mjs", import.meta.url));

const initialize = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "stdio-clean-check", version: "0" },
  },
};
const initialized = { jsonrpc: "2.0", method: "notifications/initialized" };
const toolsList = { jsonrpc: "2.0", id: 2, method: "tools/list" };
const SENT_IDS = new Set([initialize.id, toolsList.id]);
// How long stdout must stay silent after the last expected response before
// the check passes: stray writes from a tool handler land after it.
const QUIET_MS = 500;

const child = spawn(process.execPath, [bin], {
  stdio: ["pipe", "pipe", "pipe"],
});

let stdout = "";
let stderr = "";
let consumed = 0; // chars of stdout already split into complete lines
let initResponse;
let toolsResponse;
let quietTimer;
child.stdout.setEncoding("utf8");
child.stderr.setEncoding("utf8");
child.stderr.on("data", (d) => {
  stderr += d;
});

const send = (msg) => child.stdin.write(`${JSON.stringify(msg)}\n`);

// The SDK's stdio transport is newline-delimited JSON, not Content-Length.
send(initialize);

const deadline = setTimeout(() => {
  fail(
    `timed out waiting for the initialize and tools/list responses.\nstdout:\n${stdout}\nstderr:\n${stderr}`,
  );
}, 20_000);

function fail(message) {
  clearTimeout(deadline);
  clearTimeout(quietTimer);
  console.error(`stdio-clean check FAILED: ${message}`);
  child.kill("SIGKILL");
  process.exit(1);
}

child.on("error", (err) => fail(`could not spawn ${bin}: ${err.message}`));
child.on("exit", (code, signal) => {
  if (!toolsResponse) {
    fail(
      `bin exited early (code ${String(code)}, signal ${String(signal)}).\nstdout:\n${stdout}\nstderr:\n${stderr}`,
    );
  }
});

/** Every complete line must be a JSON-RPC frame we can account for. */
function inspect(line) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch (err) {
    return fail(`stdout is not a JSON-RPC frame (${err.message}):\n${line}`);
  }
  if (msg === null || typeof msg !== "object" || msg.jsonrpc !== "2.0") {
    return fail(`unexpected JSON-RPC envelope: ${line}`);
  }
  if (msg.id === undefined) {
    // A notification: needs a method and nothing response-shaped.
    if (typeof msg.method !== "string" || "result" in msg || "error" in msg) {
      return fail(`unexpected JSON-RPC envelope: ${line}`);
    }
    return;
  }
  if (!SENT_IDS.has(msg.id)) {
    return fail(`response with an id we never sent (${msg.id}): ${line}`);
  }
  if (msg.error !== undefined) {
    return fail(
      `request ${msg.id} returned an error: ${JSON.stringify(msg.error)}`,
    );
  }
  if (msg.id === initialize.id) {
    if (initResponse) return fail(`duplicate initialize response: ${line}`);
    initResponse = msg;
    const info = msg.result?.serverInfo;
    if (info?.name !== "forestrie-mcp-verify") {
      return fail(`unexpected serverInfo: ${JSON.stringify(info)}`);
    }
    send(initialized);
    send(toolsList);
  } else {
    if (toolsResponse) return fail(`duplicate tools/list response: ${line}`);
    if (!initResponse) return fail(`tools/list answered before initialize`);
    toolsResponse = msg;
    if (!Array.isArray(msg.result?.tools)) {
      return fail(`tools/list result has no tools array: ${line}`);
    }
  }
}

function arm() {
  clearTimeout(quietTimer);
  if (!toolsResponse) return;
  quietTimer = setTimeout(finish, QUIET_MS);
}

function finish() {
  clearTimeout(deadline);
  const info = initResponse.result.serverInfo;
  const count = toolsResponse.result.tools.length;
  child.removeAllListeners("exit");
  child.stdin.end();
  child.kill("SIGTERM");
  console.log(
    `stdio-clean check passed: well-formed initialize and tools/list ` +
      `(${count} tools) responses on stdout, nothing else for ${QUIET_MS} ms ` +
      `(serverInfo ${info.name} ${info.version}).`,
  );
  process.exit(0);
}

child.stdout.on("data", (d) => {
  stdout += d;
  clearTimeout(quietTimer);
  // A partial trailing line is held until its newline arrives; an
  // unterminated tail at the end of the quiet window is checked below.
  let nl;
  while ((nl = stdout.indexOf("\n", consumed)) !== -1) {
    const line = stdout.slice(consumed, nl);
    consumed = nl + 1;
    if (line.trim() !== "") inspect(line);
  }
  const tail = stdout.slice(consumed);
  if (tail.trim() !== "") {
    // Output that stays unterminated is never a valid frame.
    quietTimer = setTimeout(
      () => fail(`unterminated output on stdout: ${tail}`),
      QUIET_MS,
    );
    return;
  }
  arm();
});
