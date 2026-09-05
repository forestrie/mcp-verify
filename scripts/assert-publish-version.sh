#!/usr/bin/env bash
# assert-publish-version.sh — publish-workflow version guard.
#
# Copied from canopy/scripts/assert-publish-version.sh (FOR-365 C3) and adapted
# to a ROOT package with bare `v*` tags. Every error message is kept verbatim:
# they were clearly written after something went wrong, and each one is
# load-bearing — the E404 check, the foreign-tag arm, and the
# "success with no output" ambiguity arm especially.
#
# Two modes, selected by GITHUB_REF:
#
#   Tag build (refs/tags/v*):
#     Assert the version named by the tag equals the package's package.json
#     version, so a tag can never publish a version other than the one it
#     names. Runs before build/publish so a mismatch fails fast.
#
#   Dispatch build (anything else — workflow_dispatch recovery path):
#     Assert the package.json version is NOT already on the registry
#     (`npm view <name>@<version>` must 404), so a recovery dispatch can only
#     publish a version that has never shipped.
#
# Two changes from canopy's, both because this is a single-package repo:
#
#   1. Tags are `v<semver>`, not `<prefix>-v<semver>`, matching
#      forestrie-cli/.github/workflows/release.yml. `pkg_dir` defaults to `.`.
#   2. A GITHUB_REF-consistency check ported from forestrie-cli's
#      scripts/assert-tag-version.ts, which the canopy script lacks: when the
#      caller names an expected tag, it must be the ref actually being built.
#      That script is Bun, and D1 removes Bun; the check is worth keeping, so
#      it moves here.
#
# Usage: assert-publish-version.sh [package-dir] [expected-tag]
#   e.g. assert-publish-version.sh
#        assert-publish-version.sh . v0.1.0
#
# Requires node (to read package.json) and npm (registry lookup) on PATH.

set -euo pipefail

pkg_dir="${1:-.}"
expected_tag="${2:-}"

name=$(node -p "require('./${pkg_dir}/package.json').name")
version=$(node -p "require('./${pkg_dir}/package.json').version")
ref="${GITHUB_REF:-}"

if [ -n "$expected_tag" ] && [ -n "$ref" ] && [ "$ref" != "refs/tags/${expected_tag}" ]; then
  echo "::error::expected to be building refs/tags/${expected_tag} but GITHUB_REF is ${ref}; refusing to publish ${name} from a ref it does not name" >&2
  exit 1
fi

case "$ref" in
  "refs/tags/v"*)
    tag="${ref#refs/tags/}"
    tag_version="${tag#v}"
    if [ "$tag_version" != "$version" ]; then
      echo "::error::tag ${tag} names version ${tag_version} but ${pkg_dir}/package.json is ${version}; retag or bump so they agree" >&2
      exit 1
    fi
    echo "OK: tag ${tag} matches ${name}@${version}"
    ;;
  refs/tags/*)
    echo "::error::ref ${ref} is a tag but does not match v*; refusing to publish ${name} from a foreign tag" >&2
    exit 1
    ;;
  *)
    # workflow_dispatch (recovery only): the version must not already exist.
    set +e
    out=$(npm view "${name}@${version}" version 2>&1)
    rc=$?
    set -e
    if [ "$rc" -eq 0 ] && [ -n "$out" ]; then
      echo "::error::${name}@${version} is already published; bump ${pkg_dir}/package.json before a recovery dispatch" >&2
      exit 1
    fi
    if [ "$rc" -ne 0 ] && ! grep -q "E404" <<<"$out"; then
      echo "::error::could not determine whether ${name}@${version} exists on the registry (npm view exit ${rc})" >&2
      echo "$out" >&2
      exit 1
    fi
    if [ "$rc" -eq 0 ]; then
      # exit 0 with empty output is ambiguous — refuse rather than guess.
      echo "::error::npm view ${name}@${version} returned success with no output; refusing to proceed on ambiguity" >&2
      exit 1
    fi
    echo "OK: ${name}@${version} is not on the registry; dispatch publish may proceed"
    ;;
esac
