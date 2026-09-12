#!/usr/bin/env node
/**
 * Release-time self-registration (plan-2609-02 step 2.3).
 *
 * Writes `provenance.json` = `{name, version, gitCommit, builtAt}`
 * (`serverJsonSha256` is deferred to phase 3 — AGENTS.md forbids `server.json`
 * before the DNS record lands), signs it with `forestrie sign-statement`,
 * registers it with `forestrie register` and waits for the receipt, fetches
 * the forest's kept-copy genesis, derives the release key's public point
 * from `FORESTRIE_RELEASE_KEY_PEM`, and bundles all of it under
 * `fixtures/self/` (never committed — see .gitignore) so it ships inside the
 * npm tarball via `package.json#files`.
 *
 * The public point (`log-key.xy.b64`) exists because the publications log is
 * a grandchild of the forest root (root → auth log → publications log), and
 * neither `forestrie-cli` nor `@forestrie/receipt-verify` walks a grant
 * chain down to a child log yet — a receipt for this log verifies offline
 * under `known-log-key` (the log owner's key) today, and fails under
 * `genesis` with `delegation_invalid`. `verify_self` (step 2.4) will default
 * to `known-log-key` with this bundled point; `genesis.cbor` still ships,
 * both because it is cheap and because the walk may land later. See
 * docs/self-registration.md.
 *
 * Exit code: 0 on success, non-zero on ANY failure (a missing env var, a
 * non-zero CLI exit, a bad genesis fetch). All logging goes to stderr —
 * stdout is left silent so this composes cleanly in CI logs.
 *
 * Usage:
 *   node scripts/self-register.mjs                # real release run
 *   node scripts/self-register.mjs --dry-run       # local stubs, no network,
 *                                                   # no CLI subprocess — the
 *                                                   # gate step, and the shape
 *                                                   # exercised by the vitest
 *                                                   # `test/node/self-register.test.ts`
 *   node scripts/self-register.mjs --out-dir=<dir> # override the bundle dir
 *
 * Every external interaction (resolving the CLI binary, running it, fetching
 * genesis) is an injectable function, defaulted to the real implementation
 * unless `--dry-run` swaps in a local stub, or a caller (the test file)
 * overrides it directly — that is what makes both the dry-run path and the
 * "registration failed" path unit-testable without a network or a real key.
 *
 * CLI resolution mirrors `test/differential/cli-binary.ts`'s pin (same
 * `CLI_TAG` / sha256 map — that pinned v0.7.0 binary already has
 * `sign-statement` and `register`, confirmed via `--help`). Kept as a
 * separate copy rather than an import: that module is TypeScript, compiled
 * only for vitest, while this script ships as plain JS under `scripts/` and
 * runs via a bare `node` in the release workflow. If the two ever drift,
 * bump both together — see docs/differential-test.md. `FORESTRIE_CLI` is an
 * explicit override, so once P5 publishes `@forestrie/forestrie-cli` to npm,
 * CI can `npm install -g` it and point `FORESTRIE_CLI` at the installed
 * `forestrie` bin without this script changing at all.
 */
import { spawnSync } from "node:child_process";
import { createHash, createPublicKey, generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { arch, platform, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/** Any failure in this script — env, CLI exit, fetch — surfaces as this. */
export class SelfRegisterError extends Error {}

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

/**
 * The release key's public point, as the standard-base64 encoding of 64 raw
 * bytes `x‖y` — the same `grantData` shape `create-log --signer-pem` and the
 * CLI's `--known-log-key` expect. Derived via `node:crypto`, not the CLI:
 * `createPublicKey` accepts a PRIVATE key PEM and returns the corresponding
 * public `KeyObject`; exporting that as JWK gives base64url `x`/`y`
 * coordinates, which are decoded to 32 raw bytes each and concatenated.
 *
 * This is why the publications log's own receipts need this bundled at all
 * (see the file header): they verify under `known-log-key`, and that root
 * needs exactly this value.
 */
export function derivePublicKeyXyBase64(keyPem) {
  let publicKey;
  try {
    publicKey = createPublicKey(keyPem);
  } catch (err) {
    throw new SelfRegisterError(
      `could not derive a public key from the release key PEM: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const jwk = publicKey.export({ format: "jwk" });
  if (
    jwk.kty !== "EC" ||
    jwk.crv !== "P-256" ||
    typeof jwk.x !== "string" ||
    typeof jwk.y !== "string"
  ) {
    throw new SelfRegisterError(
      `release key is not an ES256 P-256 key (kty=${jwk.kty}, crv=${jwk.crv})`,
    );
  }
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");
  if (x.length !== 32 || y.length !== 32) {
    throw new SelfRegisterError(
      `release key's public point has an unexpected coordinate length (x=${x.length}, y=${y.length}, want 32 each)`,
    );
  }
  return Buffer.concat([x, y]).toString("base64");
}

/**
 * A fresh, throwaway ES256 P-256 private key PEM, generated in-process —
 * `--dry-run`'s stand-in for `FORESTRIE_RELEASE_KEY_PEM` so the public-point
 * derivation above runs on a real key with no fixture and no secret.
 */
function generateDryRunKeyPem() {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return privateKey.export({ type: "pkcs8", format: "pem" });
}

// ---------------------------------------------------------------------------
// Pinned reference CLI — mirrors test/differential/cli-binary.ts. See the
// file header for why this is a copy, not an import.
// ---------------------------------------------------------------------------

const CLI_TAG = "v0.7.0";
const CLI_SHA256 = Object.freeze({
  "linux-x64":
    "f211de74dc7944fb15ab652efddd0a9d6517239adea9c98cb0dd20484eccc1ed",
  "darwin-arm64":
    "a0b68282b39e491382051e2d496e677e35fd5ff814888a5fbf101d27bd0d175b",
});
const ASSET_NAMES = Object.freeze({
  "linux-x64": "forestrie-linux-x64",
  "darwin-arm64": "forestrie-darwin-arm64",
});

function currentTarget() {
  const p = platform();
  const a = arch();
  if (p === "linux" && a === "x64") return "linux-x64";
  if (p === "darwin" && a === "arm64") return "darwin-arm64";
  return null;
}

function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/**
 * Resolve the `forestrie` binary: `FORESTRIE_CLI` override first (the path
 * once CI installs `@forestrie/forestrie-cli` from npm), else the cached or
 * freshly-downloaded sha256-pinned release binary — the same one
 * `test/differential/cli-binary.ts` uses.
 */
async function defaultResolveCli({ env, log }) {
  const override = env.FORESTRIE_CLI;
  if (override !== undefined && override !== "") {
    if (!existsSync(override)) {
      throw new SelfRegisterError(`FORESTRIE_CLI='${override}' not found`);
    }
    return override;
  }

  const target = currentTarget();
  if (target === null) {
    throw new SelfRegisterError(
      `no forestrie ${CLI_TAG} release asset for ${platform()}-${arch()}; ` +
        "set FORESTRIE_CLI to a local binary (or, once @forestrie/forestrie-cli " +
        "publishes to npm, to its installed bin)",
    );
  }
  const expected = CLI_SHA256[target];
  const asset = ASSET_NAMES[target];
  const cacheDir = join(
    REPO_ROOT,
    "node_modules",
    ".cache",
    "forestrie-cli",
    CLI_TAG,
  );
  const cached = join(cacheDir, asset);

  if (existsSync(cached)) {
    const actual = sha256File(cached);
    if (actual !== expected) {
      throw new SelfRegisterError(
        `cached ${asset} has sha256 ${actual}, expected ${expected}; delete ${cacheDir} and retry`,
      );
    }
    chmodSync(cached, 0o755);
    return cached;
  }

  const url = `https://github.com/forestrie/forestrie-cli/releases/download/${CLI_TAG}/${asset}`;
  log(
    `self-register: downloading pinned forestrie CLI ${CLI_TAG} from ${url}`,
  );
  mkdirSync(cacheDir, { recursive: true });
  const tmp = `${cached}.part`;
  const res = spawnSync(
    "curl",
    ["-sSfL", "--retry", "3", "--max-time", "600", "-o", tmp, url],
    { encoding: "utf8" },
  );
  if (res.status !== 0) {
    throw new SelfRegisterError(
      `could not download ${url}: ${(res.stderr || res.error?.message || "curl failed").trim()}`,
    );
  }
  const actual = sha256File(tmp);
  if (actual !== expected) {
    throw new SelfRegisterError(
      `downloaded ${asset} has sha256 ${actual}, expected ${expected} — refusing to use it`,
    );
  }
  renameSync(tmp, cached);
  chmodSync(cached, 0o755);
  return cached;
}

/** Run the resolved CLI. Never throws: a non-zero exit is data the caller wants. */
function defaultRunCli(bin, args) {
  const res = spawnSync(bin, args, { encoding: "utf8", timeout: 300_000 });
  return {
    status: res.status ?? 1,
    stdout: res.stdout ?? "",
    stderr: res.stderr ?? "",
  };
}

/**
 * `GET {baseUrl}/api/forest/{logId}/genesis` — the forest's kept-copy
 * genesis document, the same one `verify --genesis` expects for every log in
 * the forest, child data logs included (see docs/self-registration.md for
 * the evidence trail; this is the one open item the lane-A rehearsal, step
 * 2.6, must confirm — `FORESTRIE_LOG_ID` must be the forest's bootstrap log
 * id, not the publications log's own id, because that is the exact value
 * `forestrie register --log-id` already sends as the URL's bootstrap
 * segment).
 */
async function defaultFetchGenesis(baseUrl, logId) {
  const url = `${baseUrl.replace(/\/+$/, "")}/api/forest/${logId}/genesis`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new SelfRegisterError(
      `genesis fetch failed: ${res.status} ${res.statusText} (GET ${url})`,
    );
  }
  return new Uint8Array(await res.arrayBuffer());
}

// ---------------------------------------------------------------------------
// --dry-run stubs: no network, no subprocess, no real key. Deterministic and
// entirely local, so `--dry-run` needs none of the FORESTRIE_* secrets and
// works on a fresh checkout with no cached CLI binary.
// ---------------------------------------------------------------------------

async function stubResolveCli() {
  return "forestrie-dry-run-stub";
}

function stubRunCli(_bin, args) {
  const [cmd] = args;
  const flag = (name) => {
    const i = args.indexOf(name);
    return i === -1 ? undefined : args[i + 1];
  };
  if (cmd === "sign-statement") {
    const payload = readFileSync(flag("--payload"));
    const fakeCose = Buffer.concat([
      Buffer.from("DRY-RUN-COSE-SIGN1:"),
      createHash("sha256").update(payload).digest(),
    ]);
    writeFileSync(flag("--out"), fakeCose);
    return { status: 0, stdout: "", stderr: "" };
  }
  if (cmd === "register") {
    writeFileSync(flag("--out"), Buffer.from("DRY-RUN-RECEIPT-CBOR"));
    const entryId = "0".repeat(32);
    return {
      status: 0,
      stdout: JSON.stringify({
        entryId,
        statusUrl: "dry-run://status",
        receiptUrl: "dry-run://receipt",
      }),
      stderr: "",
    };
  }
  return {
    status: 1,
    stdout: "",
    stderr: `dry-run stub: unknown command '${cmd}'`,
  };
}

async function stubFetchGenesis() {
  return new TextEncoder().encode("DRY-RUN-GENESIS-CBOR");
}

// ---------------------------------------------------------------------------
// Core flow
// ---------------------------------------------------------------------------

function readPackageJson() {
  return JSON.parse(readFileSync(join(REPO_ROOT, "package.json"), "utf8"));
}

function resolveGitCommit(env) {
  if (env.GITHUB_SHA) return env.GITHUB_SHA;
  const res = spawnSync("git", ["rev-parse", "HEAD"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  });
  if (res.status !== 0) {
    throw new SelfRegisterError(
      `git rev-parse HEAD failed: ${(res.stderr || "").trim()}`,
    );
  }
  return res.stdout.trim();
}

const DRY_RUN_DEFAULTS = Object.freeze({
  baseUrl: "https://dry-run.invalid",
  logId: "00000000-0000-0000-0000-000000000000",
  grantB64: "ZHJ5LXJ1bg==", // base64("dry-run")
});

/**
 * The full release-time flow. Every external effect is an injected function
 * so both `--dry-run` and unit tests can swap in stubs without touching a
 * network or a subprocess.
 *
 * @returns {Promise<{outDir: string, entryId: string, provenance: object}>}
 */
export async function selfRegister(opts = {}) {
  const env = opts.env ?? process.env;
  const dryRun = opts.dryRun ?? false;
  const outDir = opts.outDir ?? join(REPO_ROOT, "fixtures", "self");
  const log = opts.log ?? ((msg) => process.stderr.write(`${msg}\n`));
  const now = opts.now ?? (() => new Date());
  const resolveCli =
    opts.resolveCli ?? (dryRun ? stubResolveCli : defaultResolveCli);
  const runCli = opts.runCli ?? (dryRun ? stubRunCli : defaultRunCli);
  const fetchGenesis =
    opts.fetchGenesis ?? (dryRun ? stubFetchGenesis : defaultFetchGenesis);

  const baseUrl =
    env.FORESTRIE_BASE_URL ?? (dryRun ? DRY_RUN_DEFAULTS.baseUrl : undefined);
  const logId =
    env.FORESTRIE_LOG_ID ?? (dryRun ? DRY_RUN_DEFAULTS.logId : undefined);
  const keyPem =
    env.FORESTRIE_RELEASE_KEY_PEM ??
    (dryRun ? generateDryRunKeyPem() : undefined);
  const grantB64 =
    env.FORESTRIE_GRANT_B64 ??
    (dryRun ? DRY_RUN_DEFAULTS.grantB64 : undefined);

  if (!dryRun) {
    const missing = [
      ["FORESTRIE_BASE_URL", baseUrl],
      ["FORESTRIE_LOG_ID", logId],
      ["FORESTRIE_RELEASE_KEY_PEM", keyPem],
      ["FORESTRIE_GRANT_B64", grantB64],
    ]
      .filter(([, v]) => v === undefined || v === "")
      .map(([name]) => name);
    if (missing.length > 0) {
      throw new SelfRegisterError(
        `missing required env var(s): ${missing.join(", ")}`,
      );
    }
  }

  // Fail fast on a malformed key, before any CLI or network work.
  const publicKeyXyBase64 = derivePublicKeyXyBase64(keyPem);

  const pkg = readPackageJson();
  const gitCommit = resolveGitCommit(env);
  const builtAt = now().toISOString();
  const provenance = {
    name: pkg.name,
    version: pkg.version,
    gitCommit,
    builtAt,
  };

  const stageDir = mkdtempSync(join(tmpdir(), "mcp-verify-self-register-"));
  try {
    const provenancePath = join(stageDir, "provenance.json");
    writeFileSync(provenancePath, `${JSON.stringify(provenance, null, 2)}\n`);

    const cliBin = await resolveCli({ env, log });

    const keyPath = join(stageDir, "release-key.pem");
    writeFileSync(keyPath, keyPem, { mode: 0o600 });
    // writeFileSync's mode is masked by umask; chmod explicitly so a lax
    // umask can never leave the private key world- or group-readable.
    chmodSync(keyPath, 0o600);
    const statementPath = join(stageDir, "statement.cose");
    let signRes;
    try {
      signRes = runCli(cliBin, [
        "sign-statement",
        "--key",
        keyPath,
        "--payload",
        provenancePath,
        "--content-type",
        "application/json",
        "--out",
        statementPath,
      ]);
    } finally {
      // The private key must not outlive the one CLI invocation that needs it.
      rmSync(keyPath, { force: true });
    }
    if (signRes.status !== 0) {
      throw new SelfRegisterError(
        `forestrie sign-statement failed (exit ${signRes.status}): ${signRes.stderr.trim() || signRes.stdout.trim()}`,
      );
    }

    const receiptPath = join(stageDir, "receipt.cbor");
    const registerRes = runCli(cliBin, [
      "register",
      "--base-url",
      baseUrl,
      "--log-id",
      logId,
      "--statement",
      statementPath,
      "--grant-b64",
      grantB64,
      "--out",
      receiptPath,
      "--timeout",
      "300",
      "--json",
    ]);
    if (registerRes.status !== 0) {
      throw new SelfRegisterError(
        `forestrie register failed (exit ${registerRes.status}): ${registerRes.stderr.trim() || registerRes.stdout.trim()}`,
      );
    }
    let registerJson;
    try {
      registerJson = JSON.parse(registerRes.stdout);
    } catch {
      throw new SelfRegisterError(
        `forestrie register --json produced non-JSON stdout: ${registerRes.stdout}`,
      );
    }
    const entryId = registerJson.entryId;
    if (typeof entryId !== "string" || entryId === "") {
      throw new SelfRegisterError(
        `forestrie register --json output has no entryId: ${registerRes.stdout}`,
      );
    }

    const genesisBytes = await fetchGenesis(baseUrl, logId, { env, log });
    writeFileSync(join(stageDir, "genesis.cbor"), genesisBytes);
    writeFileSync(join(stageDir, "entry-id.txt"), entryId);
    // No trailing newline: this is the exact 64-byte-as-base64 value, not a
    // text line — the same convention as entry-id.txt above.
    writeFileSync(join(stageDir, "log-key.xy.b64"), publicKeyXyBase64);

    const bundleFiles = [
      "provenance.json",
      "statement.cose",
      "receipt.cbor",
      "genesis.cbor",
      "log-key.xy.b64",
      "entry-id.txt",
    ];
    const manifest = {
      comment:
        "Release-time self-registration bundle (plan-2609-02 step 2.3). " +
        "Generated, never committed — see fixtures/PROVENANCE.md and " +
        "docs/self-registration.md.",
      generatedAt: builtAt,
      files: Object.fromEntries(
        bundleFiles.map((f) => [
          f,
          sha256Hex(readFileSync(join(stageDir, f))),
        ]),
      ),
    };
    writeFileSync(
      join(stageDir, "manifest.json"),
      `${JSON.stringify(manifest, null, 2)}\n`,
    );

    mkdirSync(outDir, { recursive: true });
    for (const f of [...bundleFiles, "manifest.json"]) {
      copyFileSync(join(stageDir, f), join(outDir, f));
    }

    log(
      `self-register: wrote ${bundleFiles.length + 1} files to ${outDir} (entryId=${entryId})`,
    );
    return { outDir, entryId, provenance };
  } finally {
    rmSync(stageDir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// CLI bootstrap
// ---------------------------------------------------------------------------

export function parseArgs(argv) {
  let dryRun = false;
  let outDir;
  for (const arg of argv) {
    if (arg === "--dry-run") {
      dryRun = true;
    } else if (arg.startsWith("--out-dir=")) {
      outDir = arg.slice("--out-dir=".length);
    } else {
      throw new SelfRegisterError(`unknown argument: ${arg}`);
    }
  }
  return { dryRun, outDir };
}

const isMain =
  process.argv[1] !== undefined &&
  fileURLToPath(import.meta.url) === process.argv[1];

if (isMain) {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`self-register: ${err.message}\n`);
    process.exit(1);
  }
  selfRegister({
    dryRun: args.dryRun,
    ...(args.outDir ? { outDir: args.outDir } : {}),
  })
    .then(() => {
      process.exit(0);
    })
    .catch((err) => {
      process.stderr.write(
        `self-register: FAILED — ${err instanceof Error ? err.message : String(err)}\n`,
      );
      process.exit(1);
    });
}
