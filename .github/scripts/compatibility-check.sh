#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Checks the artefacts the self-test's compatibility matrix uploaded:
# one call of a Maven lane for each Maven release and Java version
# that java-maven-versions.yaml publishes. A matrix of reusable
# workflow calls hands its caller one cell's outputs alone, so the
# artefacts are the only per-cell record, and a cell missing from
# them fails here as surely as a cell that ran on the wrong toolchain.
#
# Both modes first read the cell's toolchain record, the 'mvn
# --version' a lane uploads when it runs with an artifact_suffix, and
# require the exact Maven release and the JDK the cell asked for. A
# lane that stopped forwarding mvn_version, or provisioning that fell
# back to a default, fails here rather than passing every cell on one
# Maven.
#
# verify: <dir> holds the maven-toolchain, maven-junit-reports and
#   sbom-files-maven artefacts of every cell, each in a directory
#   named after it. Each cell's Surefire reports must record the JDK
#   the cell asked for, and its SBOM must carry the fixture's
#   BOM-versioned and transitive dependencies with versions, so the
#   SBOM step resolved the graph on that Maven and JDK.
# merge: <dir> holds the maven-merge-toolchain and maven-merge-m2repo
#   artefacts of every cell; each m2repo must pass merge-check.sh
#   with jars built by the cell's JDK.
#
# Usage: compatibility-check.sh <verify|merge> <dir> <maven-json> <java-json>
# The JSON arguments are java-maven-versions.yaml's two outputs.

set -euo pipefail

mode="${1:?mode: verify or merge}"
dir="${2:?artefact directory}"
maven_json="${3:?maven versions JSON}"
java_json="${4:?java versions JSON}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

status=0
fail() {
  echo "::error::$1"
  status=1
}

mapfile -t lines < <(jq -r '.[].line' <<< "${maven_json}")
mapfile -t versions < <(jq -r '.[].version' <<< "${maven_json}")
mapfile -t javas < <(jq -r '.[]' <<< "${java_json}")
if [ "${#lines[@]}" -eq 0 ] || [ "${#javas[@]}" -eq 0 ]; then
  echo '::error::No Maven or Java versions to check'
  exit 1
fi

case "${mode}" in
  verify) toolchain_artifact='maven-toolchain' ;;
  merge) toolchain_artifact='maven-merge-toolchain' ;;
  *)
    echo "::error::Unknown mode: ${mode}"
    exit 1
    ;;
esac

cells=0
for index in "${!lines[@]}"; do
  line="${lines[${index}]}"
  maven_version="${versions[${index}]}"
  for java in "${javas[@]}"; do
    cells=$((cells + 1))
    suffix="-maven-${line}-java-${java}"
    cell="Maven ${line} / JDK ${java}"
    record="${dir}/${toolchain_artifact}${suffix}/toolchain.txt"
    if [ ! -f "${record}" ]; then
      fail "${cell}: no toolchain record"
    else
      if ! grep -qF "Apache Maven ${maven_version} (" "${record}"; then
        ran="$(sed -n 's/^Apache Maven \([^ ]*\).*/\1/p' "${record}")"
        fail "${cell}: ran Maven '${ran:-unknown}', expected ${maven_version}"
      fi
      if ! grep -qE "^Java version: ${java}[.,]" "${record}"; then
        fail "${cell}: Maven did not run on JDK ${java}"
      fi
    fi
    case "${mode}" in
      verify)
        reports="${dir}/maven-junit-reports${suffix}"
        if ! find "${reports}" -type f -name 'TEST-*.xml' 2>/dev/null \
          | grep -q .; then
          fail "${cell}: no Surefire reports"
        else
          marker="name=\"java.specification.version\" value=\"${java}\""
          wrong="$(grep -rLF --include='TEST-*.xml' "${marker}" \
            "${reports}" || true)"
          if [ -n "${wrong}" ]; then
            fail "${cell}: tests ran on another JDK: ${wrong//$'\n'/, }"
          fi
        fi
        sbom="${dir}/sbom-files-maven${suffix}/sbom-cyclonedx.json"
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
        ;;
      merge)
        m2repo="${dir}/maven-merge-m2repo${suffix}"
        if [ ! -d "${m2repo}" ]; then
          fail "${cell}: no m2repo"
        elif ! bash "${here}/merge-check.sh" "${m2repo}" '' "${java}" \
          > "${dir}/.merge-check.log" 2>&1; then
          fail "${cell}: the m2repo fails merge-check.sh"
          sed 's/^/  | /' "${dir}/.merge-check.log"
        fi
        ;;
    esac
  done
done

if [ "${status}" -eq 0 ]; then
  echo "All ${cells} ${mode} cells passed ✅"
fi
exit "${status}"
