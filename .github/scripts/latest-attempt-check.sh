# shellcheck shell=bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Run through bash, as testing.yaml does: the file is not executable.
#
# Judges each cell of the self-test's compatibility matrix by its
# latest attempt before reading its artefacts. A re-run replaces a
# cell's artefacts only when the cell uploads again, so a cell that
# passed, then failed on a later attempt before uploading anything,
# leaves the passing attempt's artefacts behind. The cell's build job,
# as this run's latest attempt left it, is the only record of how it
# ended: a cell whose build job did not succeed fails here, whatever
# artefacts exist. Each cell whose build job succeeded goes through
# compatibility-check.sh or gradle-compatibility-check.sh, unchanged,
# on that cell alone.
#
# <jobs> holds the run's jobs, as 'gh api --paginate' prints them for
# '.jobs[] | {name, conclusion}' on the run's jobs with filter=latest:
# one JSON object per job.
#
# Usage:
#   latest-attempt-check.sh <verify|merge> <jobs> <dir> <maven-json> <java-json>
#   latest-attempt-check.sh gradle <jobs> <dir> <gradle-cells-json>
# The JSON arguments are java-maven-versions.yaml's outputs, as the
# check scripts take them.

set -euo pipefail

lane="${1:?lane: verify, merge or gradle}"
jobs="${2:?jobs file}"
dir="${3:?artefact directory}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

status=0
fail() {
  echo "::error::$1"
  status=1
}

# One line per cell: its label, the build job's name in the run, and
# the arguments that hand the check script that cell alone, each
# separated by a tab.
case "${lane}" in
  verify | merge)
    maven_json="${4:?maven versions JSON}"
    java_json="${5:?java versions JSON}"
    caller='Compatibility Verify'
    if [ "${lane}" = 'merge' ]; then
      caller='Compatibility Merge'
    fi
    mapfile -t cells < <(jq -rc --arg caller "${caller}" \
      --argjson javas "${java_json}" \
      '.[] as $maven | $javas[] as $java
        | ["Maven \($maven.line) / JDK \($java)",
           "\($caller) (Maven \($maven.line), JDK \($java)) / Build",
           ([$maven] | tojson), ([$java] | tojson)]
        | join("\t")' <<< "${maven_json}")
    ;;
  gradle)
    cells_json="${4:?gradle_cells JSON}"
    mapfile -t cells < <(jq -rc \
      '.[] | ["Gradle \(.gradle.line) / JDK \(.java)",
          "Compatibility Gradle (Gradle \(.gradle.line), JDK \(.java)) / Build",
          ([.] | tojson)]
        | join("\t")' <<< "${cells_json}")
    ;;
  *)
    echo "::error::Unknown lane: ${lane}"
    exit 1
    ;;
esac
if [ "${#cells[@]}" -eq 0 ]; then
  echo "::error::No ${lane} cells to check"
  exit 1
fi

passed=0
for entry in "${cells[@]}"; do
  IFS=$'\t' read -r cell job first second <<< "${entry}"
  conclusions="$(jq -rs --arg name "${job}" \
    '[.[] | select(.name == $name) | .conclusion // "none"] | join(", ")' \
    "${jobs}")"
  if [ -z "${conclusions}" ]; then
    fail "${cell}: no '${job}' job in this run"
    continue
  fi
  if [ "${conclusions}" != 'success' ]; then
    fail "${cell}: its latest build concluded '${conclusions}'"
    continue
  fi
  if [ "${lane}" = 'gradle' ]; then
    check=(bash "${here}/gradle-compatibility-check.sh" "${dir}" "${first}")
  else
    check=(bash "${here}/compatibility-check.sh" "${lane}" "${dir}" \
      "${first}" "${second}")
  fi
  if output="$("${check[@]}" 2>&1)"; then
    passed=$((passed + 1))
  else
    printf '%s\n' "${output}"
    status=1
  fi
done

if [ "${status}" -eq 0 ]; then
  echo "All ${passed} ${lane} cells passed ✅"
fi
exit "${status}"
