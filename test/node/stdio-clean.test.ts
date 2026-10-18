/**
 * Process-level behaviour of the real bin that the in-memory transport in
 * `test/node/mcp-smoke.test.ts` cannot see: spawns `dist/node/cli.js` and
 * checks how it shuts down.
 *
 * `dist/` is a precondition this test cannot skip past silently: `beforeAll`
 * builds it (via the project's own pinned `typescript` binary,
 * `tsc -p tsconfig.build.json`) whenever it is absent, so a clean checkout
 * still gets a real answer instead of a false green.
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

const REPO_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
);
const DIST_CLI = path.join(REPO_ROOT, "dist", "node", "cli.js");
const TSC_BIN = path.join(
  REPO_ROOT,
  "node_modules",
  "typescript",
  "bin",
  "tsc",
);

let buildFailure: string | undefined;

beforeAll(() => {
  if (existsSync(DIST_CLI)) return;
  const build = spawnSync(
    process.execPath,
    [TSC_BIN, "-p", "tsconfig.build.json"],
    { cwd: REPO_ROOT, encoding: "utf8" },
  );
  if (build.status !== 0 || !existsSync(DIST_CLI)) {
    buildFailure =
      `dist/ was absent and \`tsc -p tsconfig.build.json\` did not produce ` +
      `${DIST_CLI} (exit ${String(build.status)}):\n` +
      `${build.stdout}\n${build.stderr}`;
  }
}, 60_000);

describe("stdio bin shutdown", () => {
  it("exits 0 promptly on SIGTERM while the client's stdin is still open", async () => {
    if (buildFailure !== undefined) {
      throw new Error(buildFailure);
    }
    const child = spawn(process.execPath, [DIST_CLI], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    try {
      let stdout = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (d: string) => {
        stdout += d;
      });
      const exited = new Promise<{
        code: number | null;
        signal: NodeJS.Signals | null;
      }>((resolve, reject) => {
        child.once("error", reject);
        child.once("exit", (code, signal) => resolve({ code, signal }));
      });
      child.stdin.write(
        `${JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "sigterm-test", version: "0" },
          },
        })}\n`,
      );
      const start = Date.now();
      while (!stdout.includes("\n")) {
        if (Date.now() - start > 10_000) {
          throw new Error(`no initialize response; stdout: ${stdout}`);
        }
        await new Promise((r) => setTimeout(r, 20));
      }
      // Deliberately NOT ending stdin: the client's pipe stays open.
      child.kill("SIGTERM");
      const result = await Promise.race([
        exited,
        new Promise<"timeout">((r) => setTimeout(() => r("timeout"), 2_000)),
      ]);
      expect(result).toEqual({ code: 0, signal: null });
    } finally {
      child.kill("SIGKILL");
    }
  }, 20_000);
});
