#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Checks a build lane's build artefact outputs against what the caller
# downloaded through them, holding the layout contract the README
# documents:
#
# - build_artifact_name is the expected name, or empty for shape none;
# - build_artifact_shape is the expected shape;
# - build_artifact_count equals the number of files the artefact holds;
# - for the reactor shape, every file sits at its path below
#   path_prefix, '<module>/target/<file>' for Maven and
#   '<module>/build/libs/<file>' for Gradle, so a Dockerfile in a
#   module can copy its output from the same relative path;
# - each <expected-path> names a file the artefact holds.
#
# Usage: build-artifact-check.sh <lane> <dir> <name> <shape> <count> \
#          <expected-name> <expected-shape> [<expected-path>...]
# <lane> is maven or gradle; <dir> holds the downloaded artefact, and
# is not read for shape none.

set -euo pipefail

lane="${1:?lane: maven or gradle}"
dir="${2:?artefact directory}"
# The outputs may arrive empty: a lane that stopped publishing one must
# fail the comparisons below rather than the argument check.
name="${3?build_artifact_name}"
shape="${4?build_artifact_shape}"
count="${5?build_artifact_count}"
want_name="${6?expected name}"
want_shape="${7:?expected shape}"
shift 7

status=0
fail() {
  echo "::error::${lane}: $1"
  status=1
}

if [ "${name}" != "${want_name}" ]; then
  fail "build_artifact_name '${name}', expected '${want_name}'"
fi
if [ "${shape}" != "${want_shape}" ]; then
  fail "build_artifact_shape '${shape}', expected '${want_shape}'"
fi

if [ "${want_shape}" = 'none' ]; then
  if [ "${count}" != '0' ]; then
    fail "build_artifact_count '${count}', expected 0 for shape none"
  fi
  [ "${status}" -eq 0 ] && echo "${lane}: no build artefact, as expected ✅"
  exit "${status}"
fi

files="$(cd "${dir}" && find . -type f | sed 's|^\./||' | sort)"
held="$(printf '%s\n' "${files}" | grep -c . || true)"
if [ "${count}" != "${held}" ]; then
  fail "build_artifact_count '${count}', but the artefact holds ${held}"
fi

if [ "${want_shape}" = 'reactor' ]; then
  case "${lane}" in
    maven) layout='(^|/)target/[^/]+\.(jar|war|ear)$' ;;
    gradle) layout='(^|/)build/libs/[^/]+\.(jar|war|ear)$' ;;
    *) fail "unknown lane"; exit 1 ;;
  esac
  misplaced="$(printf '%s\n' "${files}" | grep -vE "${layout}" || true)"
  if [ -n "${misplaced}" ]; then
    fail "files outside the reactor layout: ${misplaced//$'\n'/, }"
  fi
fi

for path in "$@"; do
  if ! printf '%s\n' "${files}" | grep -qxF "${path}"; then
    fail "the artefact holds no ${path}"
  fi
done

if [ "${status}" -eq 0 ]; then
  echo "${lane}: '${name}', ${shape}, ${held} file(s) ✅"
  printf '%s\n' "${files}" | sed 's/^/  /'
fi
exit "${status}"
