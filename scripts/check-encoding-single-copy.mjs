#!/usr/bin/env node
/**
 * Exactly one @forestrie/encoding in the tree.
 *
 * Several versions of @forestrie/encoding have coexisted in fresh installs
 * of the @forestrie estate. Two copies of a WIRE-TYPE package means two CBOR codecs, and a
 * verifier that disagrees with itself about the bytes is not a verifier.
 * This is a release gate, not a lint.
 *
 * Works on both layouts:
 *   pnpm  — node_modules/.pnpm/@forestrie+encoding@<v>/node_modules/@forestrie/encoding
 *   npm   — nested/flat node_modules/@forestrie/encoding/package.json
 * so the same script gates the repo AND a scratch install of the tarball.
 * The second invocation is the one that matters: it asserts what an
 * `npx -y @forestrie/mcp-verify` user actually gets, under npm's flat
 * resolver, which is not what pnpm's isolated store gives us locally.
 *
 * DO NOT "fix" a red run here with a pnpm `overrides` entry. An override
 * SILENCES the exact skew this gate exists to detect, by rewriting a
 * transitive dep to a version its parent was never tested against. Today the
 * pin is naturally satisfiable — receipt-verify@1.0.0 depends on
 * @forestrie/encoding@0.7.0 exactly, and we declare 0.7.0 exactly, so there
 * is exactly one copy without any coercion. If a future dependency drags a
 * second copy in, fix or drop that dependency (or wait for its bump), never
 * override.
 *
 * Usage: node scripts/check-encoding-single-copy.mjs [rootDir]
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const root = process.argv[2] ?? process.cwd();
const EXPECTED = "0.7.0"; // exact pin
const MAX_DEPTH = 12;

/** version -> [realpath-ish paths] */
const found = new Map();

function record(dir) {
  let pkg;
  try {
    pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  } catch {
    return;
  }
  if (pkg.name !== "@forestrie/encoding") return;
  const list = found.get(pkg.version) ?? [];
  list.push(dir);
  found.set(pkg.version, list);
}

/**
 * Walk every `node_modules` subtree looking for `@forestrie/encoding`
 * package directories. Deliberately dumb and exhaustive rather than clever
 * about layouts: pnpm's store, npm's flat tree, npm's nested fallback and a
 * yarn `node_modules` all fall out of the same walk.
 */
function walk(dir, depth) {
  if (depth > MAX_DEPTH) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (!e.isDirectory() && !e.isSymbolicLink()) continue;
    if (e.name === ".bin" || e.name === ".cache") continue;
    const p = join(dir, e.name);
    if (e.name === "encoding" && dir.endsWith(`${"@forestrie"}`)) {
      record(p);
      continue;
    }
    walk(p, depth + 1);
  }
}

walk(join(root, "node_modules"), 0);

if (found.size === 0) {
  console.error(
    `encoding-copy check FAILED: no @forestrie/encoding found under ${root}`,
  );
  process.exit(1);
}
if (found.size > 1) {
  console.error(
    "encoding-copy check FAILED: multiple @forestrie/encoding versions:",
  );
  for (const [v, paths] of found)
    for (const p of paths) console.error(`  ${v}  ${p}`);
  console.error(
    "Two wire-type codecs is two answers about the same bytes. Fix the pin, do not add an override.",
  );
  process.exit(1);
}
const [version] = [...found.keys()];
if (version !== EXPECTED) {
  console.error(
    `encoding-copy check FAILED: expected exactly ${EXPECTED}, found ${version}`,
  );
  process.exit(1);
}
console.log(
  `encoding-copy check passed: exactly one @forestrie/encoding (${version}).`,
);
