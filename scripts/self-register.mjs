#!/usr/bin/env node
/**
 * Release-time self-registration.
 *
 * Writes `provenance.json` = `{name, version, gitCommit, builtAt}`
 * (no `serverJsonSha256`), signs it with `forestrie sign-statement`,
 * delegates sealing on the publications log with `forestrie delegate` (see
 * below), registers the signed statement with `forestrie register` and
 * waits for the receipt, fetches the forest's kept-copy genesis, derives
 * the release key's public point from `FORESTRIE_RELEASE_KEY_PEM`, and
 * bundles all of it under `fixtures/self/` (never committed — see
 * .gitignore) so it ships inside the npm tarball via `package.json#files`.
 *
 * The public point (`log-key.xy.b64`) exists because the publications log is
 * a grandchild of the forest root (root → auth log → publications log), and
 * neither `forestrie-cli` nor `@forestrie/receipt-verify` walks a grant
 * chain down to a child log yet — a receipt for this log verifies offline
 * under `known-log-key` (the log owner's key) today, and fails under
 * `genesis` with `delegation_invalid`. `verify_self` defaults
 * to `known-log-key` with this bundled point; `genesis.cbor` still ships,
 * both because it is cheap and because the walk may land later. See
 * docs/self-registration.md.
 *
 * ## Delegate before register
 *
 * A receipt needs the operator's sealer to checkpoint the publications log,
 * and that requires a delegation certificate from the log owner (the
 * release key) held by the delegation coordinator. Standing delegations
 * expire (the coordinator's `STANDING_DELEGATION_TTL_SECONDS`, six hours),
 * so a release more than that long after the last `forestrie delegate`
 * stalls: `forestrie register` waits the full `--timeout 300` for a receipt
 * that never comes, because the sealer has nothing to checkpoint with. Every
 * run now delegates first, with a 24-hour `--ttl-seconds` — plenty for the
 * lease to outlive this one run — so registration never depends on a
 * standing delegation someone made by hand hours or days earlier. See
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
 * Every external interaction (resolving the CLI, running it, fetching
 * genesis) is an injectable function, defaulted to the real implementation
 * unless `--dry-run` swaps in a local stub, or a caller (the test file)
 * overrides it directly — that is what makes both the dry-run path and the
 * "registration failed" path unit-testable without a network or a real key.
 *
 * CLI resolution: `npm install --no-save` of the pinned
 * `@forestrie/forestrie-cli` into a version-keyed cache, run as `node
 * <installed dist/cli.js>`. The install-and-cache mechanics live in
 * `scripts/forestrie-cli-npm.mjs`. (This replaced a sha256-pinned v0.7.0
 * GitHub release binary and its per-platform asset matrix.)
 * `FORESTRIE_CLI` is an explicit override to a local node-runnable entry
 * point (a dev checkout's built `dist/cli.js`), for bisecting without
 * touching the npm cache.
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
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  FORESTRIE_CLI_VERSION,
  ensureForestrieCliInstalled,
} from "./forestrie-cli-npm.mjs";

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
// Pinned forestrie CLI, resolved from npm via scripts/forestrie-cli-npm.mjs.
// ---------------------------------------------------------------------------

/**
 * Resolve the `forestrie` CLI entry point: `FORESTRIE_CLI` override first (a
 * local node-runnable `dist/cli.js`, for bisecting), else `npm install
 * --no-save` of the pinned `@forestrie/forestrie-cli` into a version-keyed
 * cache (see `scripts/forestrie-cli-npm.mjs`). Returns
 * a path to a JS entry point; `defaultRunCli` runs it as `node <entry>
 * <args>`.
 */
async function defaultResolveCli({ env, log }) {
  const override = env.FORESTRIE_CLI;
  if (override !== undefined && override !== "") {
    if (!existsSync(override)) {
      throw new SelfRegisterError(`FORESTRIE_CLI='${override}' not found`);
    }
    return override;
  }

  try {
    return ensureForestrieCliInstalled(REPO_ROOT, {
      version: FORESTRIE_CLI_VERSION,
      log,
    });
  } catch (err) {
    throw new SelfRegisterError(
      err instanceof Error ? err.message : String(err),
    );
  }
}

/**
 * Run the resolved CLI entry point under the same `node` running this
 * script — never execed directly, since npm ships `@forestrie/forestrie-cli`
 * as plain JS (`bin: { forestrie: "dist/cli.js" }`), not a platform binary.
 * Never throws: a non-zero exit is data the caller wants.
 */
function defaultRunCli(entry, args) {
  const res = spawnSync(process.execPath, [entry, ...args], {
    encoding: "utf8",
    timeout: 300_000,
  });
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
 * the evidence trail; confirmed for lane A, and the thing to re-check on any
 * new lane — `FORESTRIE_LOG_ID` must be the forest's bootstrap log
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
  if (cmd === "delegate") {
    return {
      status: 0,
      stdout: JSON.stringify({
        command: "delegate",
        status: "submitted",
        logId: flag("--log-id"),
        sealerId: "dry-run-sealer",
        epoch: 0,
        mmrStart: 0,
        mmrEnd: 9007199254740991,
        expiresAt: "1970-01-01T00:00:00.000Z",
      }),
      stderr: "",
    };
  }
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
  coordinatorUrl: "https://dry-run-coordinator.invalid",
  knownSealerKey: "ZHJ5LXJ1bi1zZWFsZXItdm91Y2hlci1rZXktMzItYnl0ZXMtLS0=",
  publicationsLogId: "11111111-1111-1111-1111-111111111111",
});

/** `forestrie delegate`'s lease TTL — 24h, plenty to outlive this one run. */
const DELEGATE_TTL_SECONDS = "86400";

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
  // The delegation coordinator and the sealer voucher key it checks
  // `forestrie delegate` against — both public values, GitHub Actions
  // `vars.*` in the npm-publish environment (see docs/self-registration.md).
  const coordinatorUrl =
    env.DELEGATION_COORDINATOR_URL ??
    (dryRun ? DRY_RUN_DEFAULTS.coordinatorUrl : undefined);
  const knownSealerKey =
    env.KNOWN_SEALER_KEY ??
    (dryRun ? DRY_RUN_DEFAULTS.knownSealerKey : undefined);
  // The publications log itself — a grandchild of the forest root named by
  // FORESTRIE_LOG_ID (see "The grant chain" in docs/self-registration.md).
  // Nothing in this script derives it from FORESTRIE_GRANT_B64 today (the
  // CLI decodes the grant internally for `register`), so it is its own var
  // rather than a duplicate parse of the grant.
  const publicationsLogId =
    env.FORESTRIE_PUBLICATIONS_LOG_ID ??
    (dryRun ? DRY_RUN_DEFAULTS.publicationsLogId : undefined);

  if (!dryRun) {
    const missing = [
      ["FORESTRIE_BASE_URL", baseUrl],
      ["FORESTRIE_LOG_ID", logId],
      ["FORESTRIE_RELEASE_KEY_PEM", keyPem],
      ["FORESTRIE_GRANT_B64", grantB64],
      ["DELEGATION_COORDINATOR_URL", coordinatorUrl],
      ["KNOWN_SEALER_KEY", knownSealerKey],
      ["FORESTRIE_PUBLICATIONS_LOG_ID", publicationsLogId],
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
    let delegateRes;
    try {
      // Delegate BEFORE registering: a receipt needs the operator's sealer
      // to checkpoint the publications log, and that needs a fresh
      // delegation certificate from this log-owner key held by the
      // coordinator — see the file header. Runs on the same path as
      // sign-statement/register (real CLI or dry-run stub alike), so a
      // rehearsal dispatch delegates for real exactly when it registers for
      // real, and --dry-run stubs both together.
      delegateRes = runCli(cliBin, [
        "delegate",
        "--coordinator-url",
        coordinatorUrl,
        "--log-id",
        publicationsLogId,
        "--sign-with",
        keyPath,
        "--known-sealer-key",
        knownSealerKey,
        "--ttl-seconds",
        DELEGATE_TTL_SECONDS,
        "--json",
      ]);
      if (delegateRes.status !== 0) {
        throw new SelfRegisterError(
          `forestrie delegate failed (exit ${delegateRes.status}): ${delegateRes.stderr.trim() || delegateRes.stdout.trim()}`,
        );
      }
      let delegateJson;
      try {
        delegateJson = JSON.parse(delegateRes.stdout);
      } catch {
        throw new SelfRegisterError(
          `forestrie delegate --json produced non-JSON stdout: ${delegateRes.stdout}`,
        );
      }
      log(
        `self-register: delegated sealer for log ${publicationsLogId} ` +
          `(expiresAt=${delegateJson.expiresAt}, mmrEnd=${delegateJson.mmrEnd})`,
      );

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
      // The private key must not outlive the CLI invocations that need it.
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
        "Release-time self-registration bundle. " +
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
