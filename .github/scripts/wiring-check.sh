#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Checks what the self-test fixtures cannot exercise:
#
# - the guard steps' accept and reject paths, run as extracted from
#   the workflows, so a change to a guard shows up here;
# - the Gerrit submodule initialisation, against a local change that
#   adds a submodule, which a plain 'git submodule update' skips;
# - the submodule wiring of every checkout in both lanes.
#
# Run from the repository root: bash .github/scripts/wiring-check.sh

set -euo pipefail

maven='.github/workflows/maven-build-test.yaml'
gradle='.github/workflows/gradle-build-test.yaml'
# The literal expression each checkout must pass, not a shell expansion.
# shellcheck disable=SC2016
wiring='${{ inputs.checkout_submodules }}'
init_step='Initialise Gerrit change submodules'
checkout_uses='^(actions/checkout|lfreleng-actions/checkout-gerrit-change-action)@'

status=0
fail() {
  echo "::error::$*"
  status=1
}

tmp="$(mktemp -d)"
trap 'rm -rf -- "${tmp}"' EXIT

# Write the run script of step "$3" in job "$2" of workflow "$1" to "$4".
extract() {
  JOB="$2" STEP="$3" yq -e '.jobs | to_entries | .[]
    | select(.key == strenv(JOB)) | .value.steps[]
    | select(.name == strenv(STEP)) | .run' "$1" > "$4"
}

# Run script "$3" with the VAR=value pairs that follow, and compare its
# verdict with "$1" (pass or fail); "$2" labels the case.
expect() {
  local want="$1" label="$2" script="$3" got='pass'
  shift 3
  : > "${tmp}/output"
  if ! env GITHUB_OUTPUT="${tmp}/output" "$@" bash "${script}" \
    > "${tmp}/log" 2>&1; then
    got='fail'
  fi
  if [ "${got}" != "${want}" ]; then
    fail "${label}: expected ${want}, got ${got}"
    sed 's/^/  | /' "${tmp}/log"
  fi
}

# Compare the metadata_path the last expect() run wrote with "$2".
expect_path() {
  local got
  got="$(sed -n 's/^metadata_path=//p' "${tmp}/output")"
  if [ "${got}" != "$2" ]; then
    fail "$1: metadata_path '${got}', expected '$2'"
  fi
}

echo 'SBOM job: POM guard'
pom_guard="${tmp}/pom-guard.sh"
extract "${maven}" sbom 'Require the POM the SBOM resolves' "${pom_guard}"
for pom in '' 'pom.xml' './pom.xml' '././pom.xml'; do
  expect pass "POM guard accepts '${pom}'" "${pom_guard}" \
    "MVN_POM_FILE=${pom}"
done
for pom in 'core/pom.xml' 'build-pom.xml' 'pom.xml/'; do
  expect fail "POM guard rejects '${pom}'" "${pom_guard}" \
    "MVN_POM_FILE=${pom}"
done
expect fail 'POM guard rejects a line break' "${pom_guard}" \
  "MVN_POM_FILE=x"$'\n'"::warning::injected"
if grep -q '^::warning::' "${tmp}/log"; then
  fail 'POM guard let a line break start a workflow command'
fi

echo 'SBOM job: environment guard'
env_guard="${tmp}/env-guard.sh"
extract "${maven}" sbom 'Require an environment the SBOM can reproduce' \
  "${env_guard}"
for value in '' '{}' '{"MAVEN_OPTS": "-Dx=y"}' '{"my_flag": "1"}' \
  '{"_x": "1", "My_Flag2": "1"}'; do
  expect pass "environment guard accepts ${value:-empty}" "${env_guard}" \
    "ENV_VARS=${value}"
done
for value in '[]' '"text"' 'not json' '{"MAVEN_ARGS": "-f x"}' \
  '{"maven_args": "-f x"}' '{"JAVA_VERSION": "8"}' \
  '{"MVN_OPTS": "-Dx"}'; do
  expect fail "environment guard rejects ${value}" "${env_guard}" \
    "ENV_VARS=${value}"
done
# Names JavaScript's toUpperCase() maps onto reserved ones (U+017F
# and U+0131 upper-case to S and I) and other non-identifiers. The
# JSON escapes keep this script ASCII and the case locale-independent.
for value in '{"maven_arg\u017f": "-f x"}' '{"path_pref\u0131x": "x"}' \
  '{"": "x"}' '{"1ST": "x"}' '{"MY-FLAG": "x"}' \
  '{"MY_FLAG\nMAVEN_ARGS": "x"}'; do
  expect fail "environment guard rejects the name in ${value}" \
    "${env_guard}" "ENV_VARS=${value}"
done
# The first case must be a bypass without the ASCII check, or it tests
# nothing: prove the action would export it as MAVEN_ARGS.
if command -v node > /dev/null; then
  upper="$(node -e 'console.log("maven_arg\u017f".toUpperCase())')"
  if [ "${upper}" != 'MAVEN_ARGS' ]; then
    fail "toUpperCase() maps the U+017F case to '${upper}', not MAVEN_ARGS"
  fi
fi

echo 'Build job: POM location for metadata'
locate="${tmp}/locate.sh"
extract "${maven}" build 'Locate the POM for metadata' "${locate}"
expect pass 'default POM' "${locate}" \
  PATH_PREFIX=. MVN_POM_FILE= JAVA_VERSION=
expect_path 'default POM' '.'
expect pass 'root POM' "${locate}" \
  PATH_PREFIX=. MVN_POM_FILE=./pom.xml JAVA_VERSION=
expect_path 'root POM' '.'
expect pass 'subdirectory POM' "${locate}" \
  PATH_PREFIX=repo MVN_POM_FILE=core/pom.xml JAVA_VERSION=
expect_path 'subdirectory POM' 'repo/core'
expect fail 'unreadable POM without java_version' "${locate}" \
  PATH_PREFIX=. MVN_POM_FILE=build-pom.xml JAVA_VERSION=
expect pass 'unreadable POM with java_version' "${locate}" \
  PATH_PREFIX=. MVN_POM_FILE=build-pom.xml JAVA_VERSION=17
expect_path 'unreadable POM with java_version' '.'
expect fail 'line break in path_prefix' "${locate}" \
  "PATH_PREFIX=a"$'\n'"b" MVN_POM_FILE= JAVA_VERSION=

echo 'Checkouts: submodule wiring'
for workflow in "${maven}" "${gradle}"; do
  checkouts="$(USES="${checkout_uses}" yq '[.jobs[].steps[]
    | select((.uses // "") | test(strenv(USES)))] | length' "${workflow}")"
  if [ "${checkouts}" -eq 0 ]; then
    fail "${workflow}: found no checkout steps"
  fi
  # $job is a yq variable, not a shell expansion.
  # shellcheck disable=SC2016
  unwired="$(USES="${checkout_uses}" WIRING="${wiring}" yq -r '.jobs
    | to_entries | .[] | .key as $job | .value.steps[]
    | select((.uses // "") | test(strenv(USES)))
    | select(.with.submodules != strenv(WIRING))
    | $job + ": " + .name' "${workflow}")"
  if [ -n "${unwired}" ]; then
    fail "${workflow}: checkouts without submodule wiring:" \
      "${unwired//$'\n'/, }"
  fi
  # Every Gerrit checkout must be followed by the initialisation step.
  followers="$(yq -o=json '.' "${workflow}" | jq -r '.jobs[] | .steps
    | . as $steps | to_entries[]
    | select((.value.uses // "")
      | test("^lfreleng-actions/checkout-gerrit-change-action@"))
    | ($steps[.key + 1].name // "none")')"
  while IFS= read -r follower; do
    if [ "${follower}" != "${init_step}" ]; then
      fail "${workflow}: a Gerrit checkout is followed by '${follower}'"
    fi
  done <<< "${followers}"
  echo "  ${workflow}: ${checkouts} checkouts wired"
done
variants="$(STEP="${init_step}" yq ea -r '[.jobs[].steps[]
  | select(.name == strenv(STEP)) | .if + "\n" + .run] | unique | length' \
  "${maven}" "${gradle}" | sort -u)"
if [ "${variants}" != '1' ]; then
  fail "the '${init_step}' steps differ between jobs or lanes"
fi

echo 'Gerrit checkout: submodules a change adds'
init="${tmp}/init.sh"
extract "${maven}" build "${init_step}" "${init}"
(
  # Local repositories, isolated from the caller's own git settings
  # (submodule.recurse, for one, changes what a switch does): an
  # identity, no signing, and file transport for the submodule, which
  # git refuses by default.
  export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
  export GIT_CONFIG_COUNT=5
  export GIT_CONFIG_KEY_0=user.name GIT_CONFIG_VALUE_0='Wiring Check'
  export GIT_CONFIG_KEY_1=user.email GIT_CONFIG_VALUE_1='wiring@example.org'
  export GIT_CONFIG_KEY_2=commit.gpgsign GIT_CONFIG_VALUE_2=false
  export GIT_CONFIG_KEY_3=protocol.file.allow GIT_CONFIG_VALUE_3=always
  export GIT_CONFIG_KEY_4=init.defaultBranch GIT_CONFIG_VALUE_4=main
  git init -q "${tmp}/module"
  echo 'module content' > "${tmp}/module/README"
  git -C "${tmp}/module" add README
  git -C "${tmp}/module" commit -q -m 'Module'
  git init -q "${tmp}/project"
  echo 'base' > "${tmp}/project/README"
  git -C "${tmp}/project" add README
  git -C "${tmp}/project" commit -q -m 'Base'
  git -C "${tmp}/project" switch -q -c change
  git -C "${tmp}/project" submodule --quiet add "${tmp}/module" module
  git -C "${tmp}/project" commit -q -m 'Add a submodule'
  git -C "${tmp}/project" switch -q main
  # What checkout-gerrit-change-action v1.1.0 does: actions/checkout
  # v7.0.1 checks out the base, then runs 'submodule sync' and
  # 'submodule update --init --force', registering the submodules the
  # base has. The action then fetches the change, switches to it, and
  # runs a plain update, which leaves a newly added one inactive.
  git clone -q "${tmp}/project" "${tmp}/checkout"
  git -C "${tmp}/checkout" submodule sync
  git -C "${tmp}/checkout" submodule update --init --force
  git -C "${tmp}/checkout" fetch -q origin change
  git -C "${tmp}/checkout" checkout -q FETCH_HEAD
  git -C "${tmp}/checkout" submodule update
  if [ -e "${tmp}/checkout/module/README" ]; then
    echo '::error::the plain update initialised the new submodule, so' \
      'this case no longer tests anything'
    exit 1
  fi
  (cd "${tmp}/checkout" && bash "${init}")
  if [ ! -e "${tmp}/checkout/module/README" ]; then
    echo '::error::the initialisation step left a new submodule empty'
    exit 1
  fi
) || status=1

if [ "${status}" -eq 0 ]; then
  echo 'Wiring check passed ✅'
fi
exit "${status}"
