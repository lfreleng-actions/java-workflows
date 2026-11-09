#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Checks the artefacts the self-test's Gradle compatibility matrix
# uploaded: one call of the Gradle lane for each Gradle release and
# Java version in java-maven-versions.yaml's gradle_cells. A matrix of
# reusable workflow calls hands its caller one cell's outputs alone,
# so the artefacts are the only per-cell record, and a cell missing
# from them fails here as surely as one that ran the wrong toolchain.
#
# Each cell's toolchain record, the 'gradle --version' the lane
# uploads when it runs with an artifact_suffix, must name the exact
# Gradle release and a launcher JVM on the cell's Java version. The
# launcher is the evidence for the JDK that ran Gradle: the fixture
# compiles and tests through a Java toolchain of its own, so its test
# reports record that toolchain's version, not the cell's. Each cell
# must also have test reports, and an SBOM carrying the fixture's
# BOM-versioned and transitive dependencies with versions, so the
# SBOM step resolved the graph on that Gradle and JDK.
#
# Usage: gradle-compatibility-check.sh <dir> <gradle-cells-json>
# <dir> holds every cell's gradle-toolchain, gradle-junit-reports and
# sbom-files-gradle artefacts, each in a directory named after it.

set -euo pipefail

dir="${1:?artefact directory}"
cells_json="${2:?gradle_cells JSON}"

status=0
fail() {
  echo "::error::$1"
  status=1
}

mapfile -t cells < <(jq -r \
  '.[] | "\(.gradle.line) \(.gradle.version) \(.java)"' <<< "${cells_json}")
if [ "${#cells[@]}" -eq 0 ]; then
  echo '::error::No Gradle cells to check'
  exit 1
fi

for cell_spec in "${cells[@]}"; do
  read -r line version java <<< "${cell_spec}"
  suffix="-gradle-${line}-java-${java}"
  cell="Gradle ${line} / JDK ${java}"

  record="${dir}/gradle-toolchain${suffix}/toolchain.txt"
  if [ ! -f "${record}" ]; then
    fail "${cell}: no toolchain record"
  else
    if ! grep -qxF "Gradle ${version}" "${record}"; then
      ran="$(sed -n 's/^Gradle \([^ ]*\)$/\1/p' "${record}")"
      fail "${cell}: ran Gradle '${ran:-unknown}', expected ${version}"
    fi
    if ! grep -qE "^Launcher JVM: +${java}([.+ ]|$)" "${record}"; then
      fail "${cell}: Gradle did not run on JDK ${java}"
    fi
  fi

  if ! find "${dir}/gradle-junit-reports${suffix}" -type f \
    -name 'TEST-*.xml' 2>/dev/null | grep -q .; then
    fail "${cell}: no test reports"
  fi

  sbom="${dir}/sbom-files-gradle${suffix}/sbom-cyclonedx.json"
  if [ ! -f "${sbom}" ]; then
    fail "${cell}: no SBOM"
  else
    for coordinate in com.fasterxml.jackson.core:jackson-databind \
      com.fasterxml.jackson.core:jackson-core; do
      component_version="$(jq -r --arg g "${coordinate%%:*}" \
        --arg a "${coordinate#*:}" \
        '[.components[]? | select(.group == $g and .name == $a)
          | .version // ""] | first // ""' "${sbom}")"
      if [ -z "${component_version}" ] \
        || [ "${component_version}" = 'UNKNOWN' ]; then
        fail "${cell}: ${coordinate} missing or unversioned in SBOM"
      fi
    done
  fi
done

if [ "${status}" -eq 0 ]; then
  echo "All ${#cells[@]} Gradle cells passed ✅"
fi
exit "${status}"
