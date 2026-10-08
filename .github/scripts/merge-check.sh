#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Checks the m2repo a self-test call of the Maven merge lane handed to
# its publish step, against test-maven-project:
#
# - each fixture module's timestamped SNAPSHOT at buildNumber 1, with
#   its version-level metadata (ONAP's Nexus has never published the
#   org.lfreleng.test group, so every module takes the first-publish
#   path);
# - no non-timestamped SNAPSHOT jar, and nothing outside the group;
# - with a dry-run count, a dry run that covered every file;
# - with a Java version, jars built by that JDK, read from the
#   Build-Jdk-Spec maven-jar-plugin writes into each manifest. This is
#   how a matrix cell proves it ran on the JDK it asked for: the lane's
#   job outputs reach the caller from one cell alone.
#
# Usage: merge-check.sh <m2repo-dir> [<dry-run-count> [<java-version>]]
# An empty dry-run count skips that check.

set -euo pipefail

m2repo="${1:?m2repo directory}"
dry_run_count="${2:-}"
java_version="${3:-}"

status=0
fail() {
  echo "::error::$1"
  status=1
}

group="${m2repo}/org/lfreleng/test"
stamp='1\.0\.0-[0-9]{8}\.[0-9]{6}-1'
for module in project:pom parent:pom core:jar app:jar; do
  artifact="test-maven-${module%%:*}"
  dir="${group}/${artifact}/1.0.0-SNAPSHOT"
  if [ ! -f "${dir}/maven-metadata.xml" ]; then
    fail "${artifact}: no version-level maven-metadata.xml"
  elif ! grep -q '<buildNumber>1</buildNumber>' \
    "${dir}/maven-metadata.xml"; then
    fail "${artifact}: metadata does not start at buildNumber 1"
  fi
  for type in pom "${module##*:}"; do
    if ! find "${dir}" -type f \
      | grep -Eq "/${artifact}-${stamp}\.${type}\$"; then
      fail "${artifact}: no timestamped .${type} at buildNumber 1"
    fi
  done
done
if find "${m2repo}" -type f -name '*-SNAPSHOT.jar' | grep -q .; then
  fail 'the m2repo holds a non-timestamped SNAPSHOT jar'
fi
outside="$(find "${m2repo}" -type f ! -path "${group}/*" | wc -l)"
if [ "${outside}" -ne 0 ]; then
  fail "${outside} file(s) lie outside org/lfreleng/test"
fi
files="$(find "${m2repo}" -type f | wc -l | tr -d ' ')"
if [ -n "${dry_run_count}" ] && [ "${dry_run_count}" != "${files}" ]; then
  fail "dry run covers '${dry_run_count}' of ${files} file(s)"
fi
echo "${files} file(s); dry run covers ${dry_run_count:-(not checked)}"

if [ -n "${java_version}" ]; then
  jars=0
  wrong=0
  while IFS= read -r -d '' jar; do
    jars=$((jars + 1))
    built="$(unzip -p "${jar}" META-INF/MANIFEST.MF \
      | sed -n 's/^Build-Jdk-Spec: *\([0-9]*\).*/\1/p')"
    if [ "${built}" != "${java_version}" ]; then
      fail "${jar#"${m2repo}/"} built by JDK '${built}', expected ${java_version}"
      wrong=$((wrong + 1))
    fi
  done < <(find "${group}" -type f -name '*.jar' -print0)
  if [ "${jars}" -eq 0 ]; then
    fail 'no jar to read the build JDK from'
  elif [ "${wrong}" -eq 0 ]; then
    echo "${jars} jar(s) built by JDK ${java_version}"
  fi
fi

exit "${status}"
