/**
 * `scripts/self-register.mjs` — the dry-run path and the "registration
 * failed" path, with the CLI invocation mocked so this needs neither a
 * network nor a real `forestrie` binary.
 *
 * The script lives under `scripts/`, not `src/`, so it is exercised directly
 * via dynamic import rather than through the package's public surface. It
 * still runs inside the unit project's forbidden-fetch setup (D2(b)); the
 * dry-run path proves it never calls the real `fetch`.
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  SelfRegisterError,
  derivePublicKeyXyBase64,
  selfRegister,
} from "../../scripts/self-register.mjs";

/**
 * A fixed EC P-256 private key (PKCS8), generated once for this test. Its
 * expected public point below was derived independently — not via
 * `derivePublicKeyXyBase64`'s own JWK path, but by exporting the public key
 * as SPKI DER and reading the raw uncompressed point (0x04 ‖ X ‖ Y) out of
 * its last 65 bytes — so this is a real cross-check, not a tautology.
 */
const KNOWN_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgy1eEcJsD9XeAVVP+
out1i8ljt8CpCj9hBsNf64gy41ehRANCAAT/ILKbVnzN2S0kZ+8MM3TpOP7q40Pi
bmUlvkLTERJrM8OGFWqKFHNhsuVf9rFC8fv46Uh8Ds1PkohxablveQVh
-----END PRIVATE KEY-----
`;
const KNOWN_PEM_XY_BASE64 =
  "/yCym1Z8zdktJGfvDDN06Tj+6uND4m5lJb5C0xESazPDhhVqihRzYbLlX/axQvH7+OlIfA7NT5KIcWm5b3kFYQ==";

/** The path after `--out` in a mocked CLI invocation's argv. */
function outPathOf(args: string[]): string {
  const idx = args.indexOf("--out");
  const path = args[idx + 1];
  if (path === undefined) throw new Error("no --out in mocked CLI args");
  return path;
}

let outDir: string;

beforeEach(() => {
  outDir = mkdtempSync(join(tmpdir(), "mcp-verify-self-register-test-"));
});

afterEach(() => {
  rmSync(outDir, { recursive: true, force: true });
});

describe("derivePublicKeyXyBase64", () => {
  it("a known PEM produces the expected 64-byte x‖y value", () => {
    const got = derivePublicKeyXyBase64(KNOWN_PEM);
    expect(got).toBe(KNOWN_PEM_XY_BASE64);
    expect(Buffer.from(got, "base64")).toHaveLength(64);
  });

  it("rejects a key that is not valid PEM", () => {
    expect(() => derivePublicKeyXyBase64("not a pem")).toThrow(
      SelfRegisterError,
    );
  });
});

describe("selfRegister --dry-run", () => {
  it("writes the full bundle with no network and no real CLI", async () => {
    const result = await selfRegister({ dryRun: true, outDir });

    expect(result.entryId).toBe("0".repeat(32));
    expect(result.outDir).toBe(outDir);
    expect(result.provenance).toMatchObject({
      name: "@forestrie/mcp-verify",
    });

    const files = [
      "provenance.json",
      "statement.cose",
      "receipt.cbor",
      "genesis.cbor",
      "log-key.xy.b64",
      "entry-id.txt",
      "manifest.json",
    ];
    for (const f of files) {
      expect(() => readFileSync(join(outDir, f))).not.toThrow();
    }

    const provenance = JSON.parse(
      readFileSync(join(outDir, "provenance.json"), "utf8"),
    );
    expect(provenance).toEqual(
      expect.objectContaining({
        name: "@forestrie/mcp-verify",
        version: expect.any(String),
        gitCommit: expect.stringMatching(/^[0-9a-f]{40}$/),
        builtAt: expect.any(String),
      }),
    );
    // D4: serverJsonSha256 is deferred to phase 3 — must NOT appear yet.
    expect(provenance).not.toHaveProperty("serverJsonSha256");

    const manifest = JSON.parse(
      readFileSync(join(outDir, "manifest.json"), "utf8"),
    );
    for (const f of files.filter((f) => f !== "manifest.json")) {
      expect(manifest.files[f]).toMatch(/^[0-9a-f]{64}$/);
    }

    expect(readFileSync(join(outDir, "entry-id.txt"), "utf8")).toBe(
      "0".repeat(32),
    );

    // The throwaway dry-run key's public point: still a real 64-byte x‖y,
    // just not tied to any secret.
    const logKeyXy = readFileSync(join(outDir, "log-key.xy.b64"), "utf8");
    expect(Buffer.from(logKeyXy, "base64")).toHaveLength(64);
  });

  it("never touches the real fetch (the unit project's forbidden-fetch global)", async () => {
    // If the dry-run path fell through to defaultFetchGenesis, the global
    // forbidden fetch (test/setup/forbidden-fetch.ts) would throw and this
    // would reject instead of resolving.
    await expect(
      selfRegister({ dryRun: true, outDir }),
    ).resolves.toBeDefined();
  });
});

describe("selfRegister failure paths", () => {
  it("a non-zero `forestrie register` exit fails the whole run", async () => {
    let sawRegisterArgs: string[] | undefined;
    await expect(
      selfRegister({
        dryRun: true,
        outDir,
        runCli: (bin: string, args: string[]) => {
          if (args[0] === "register") {
            sawRegisterArgs = args;
            return {
              status: 1,
              stdout: "",
              stderr: "registration_failed: 429 from lane",
            };
          }
          // sign-statement still succeeds — proves the failure is
          // specifically attributed to register, not a fall-through.
          writeFileSync(outPathOf(args), "stub-cose");
          return { status: 0, stdout: "", stderr: "" };
        },
      }),
    ).rejects.toThrow(SelfRegisterError);

    expect(sawRegisterArgs).toBeDefined();
    expect(sawRegisterArgs).toContain("--timeout");
    expect(sawRegisterArgs).toContain("300");
    expect(sawRegisterArgs).toContain("--json");
  });

  it("does not leave a partial bundle in outDir on failure", async () => {
    await expect(
      selfRegister({
        dryRun: true,
        outDir,
        runCli: () => ({ status: 1, stdout: "", stderr: "boom" }),
      }),
    ).rejects.toThrow();

    // outDir was created by beforeEach but selfRegister must not have
    // populated it — mkdirSync(outDir) only happens after every step
    // succeeds.
    expect(() => readFileSync(join(outDir, "manifest.json"))).toThrow();
  });

  it("a missing required env var fails closed outside --dry-run", async () => {
    await expect(
      selfRegister({ dryRun: false, outDir, env: {} }),
    ).rejects.toThrow(/FORESTRIE_BASE_URL/);
  });

  it("register --json output with no entryId is a failure, not a crash", async () => {
    await expect(
      selfRegister({
        dryRun: true,
        outDir,
        runCli: (bin: string, args: string[]) => {
          if (args[0] === "register") {
            writeFileSync(outPathOf(args), "receipt");
            return { status: 0, stdout: "{}", stderr: "" };
          }
          writeFileSync(outPathOf(args), "stub-cose");
          return { status: 0, stdout: "", stderr: "" };
        },
      }),
    ).rejects.toThrow(/entryId/);
  });
});
