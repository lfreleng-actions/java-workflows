#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Checks what the self-test fixtures cannot exercise:
#
# - the guard steps' accept and reject paths, run as extracted from
#   the workflows, so a change to a guard shows up here, and the merge
#   lane's copies of them, which must match the verify lane's;
# - the merge lane's input validation, including the branch its
#   checkouts build, and its m2repo checks, whose reject paths guard
#   the publish;
# - the merge lane's copy of maven-build-action's workspace placeholder
#   expansion, against the vendored script at the pinned SHA;
# - the Gerrit submodule initialisation, against a local change that
#   adds a submodule, which a plain 'git submodule update' skips;
# - the submodule wiring of every checkout in all three lanes.
#
# Run from the repository root: bash .github/scripts/wiring-check.sh

set -euo pipefail

maven='.github/workflows/maven-build-test.yaml'
gradle='.github/workflows/gradle-build-test.yaml'
merge='.github/workflows/maven-merge.yaml'
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
  expect_output "$1" metadata_path "$2"
}

# Compare output "$2" of the last expect() run with "$3"; "$1" labels it.
expect_output() {
  local got
  got="$(sed -n "s/^$2=//p" "${tmp}/output")"
  if [ "${got}" != "$3" ]; then
    fail "$1: $2 '${got}', expected '$3'"
  fi
}

echo 'Build job: SBOM POM guard'
pom_guard="${tmp}/pom-guard.sh"
extract "${maven}" build 'Require the POM the SBOM resolves' "${pom_guard}"
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

echo 'Build job: SBOM environment guard'
env_guard="${tmp}/env-guard.sh"
extract "${maven}" build 'Require an environment the SBOM can reproduce' \
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

# The merge lane runs the same three steps, tested above through the
# verify lane's copies, so its own must not drift from them. The whole
# step is compared, since its if:, env: or shell: can break it as
# surely as its script.
echo 'Merge lane: guards match the verify lane'
for step in 'Require the POM the SBOM resolves' \
  'Require an environment the SBOM can reproduce' \
  'Locate the POM for metadata'; do
  for pair in "${maven}:verify" "${merge}:merge"; do
    JOB=build STEP="${step}" yq -e -o=json '.jobs | to_entries | .[]
      | select(.key == strenv(JOB)) | .value.steps[]
      | select(.name == strenv(STEP))' "${pair%%:*}" \
      > "${tmp}/${pair##*:}-step.json"
  done
  if ! cmp -s "${tmp}/verify-step.json" "${tmp}/merge-step.json"; then
    fail "${merge}: '${step}' differs from the verify lane's"
  fi
done

echo 'Merge lane: input validation'
validate="${tmp}/validate.sh"
extract "${merge}" validate 'Validate inputs' "${validate}"
merge_inputs() {
  expect "$1" "$2" "${validate}" "NEXUS_SERVER=$3" \
    "REPOSITORY_NAME=${4-snapshots}" "NEXUS_USERNAME=${5-}" \
    'TARGET_REPOSITORY=example-org/example-repo' \
    'CALLER_REPOSITORY=example-org/example-repo' \
    'GERRIT_BRANCH=' 'BRANCH_INPUT=' 'TRIGGER_REF=refs/heads/main'
}
merge_inputs pass 'plain server' 'https://nexus.example.org'
expect_output 'plain server' nexus_endpoint 'nexus.example.org:443'
expect_output 'plain server' nexus_username 'example-repo'
merge_inputs pass 'port, path, trailing slash and username' \
  'https://nexus.example.org:08443/nexus/' snapshots 'deployer'
expect_output 'port and path' nexus_endpoint 'nexus.example.org:8443'
expect_output 'explicit username' nexus_username 'deployer'
for server in '' 'http://nexus.example.org' 'https://nexus.example.org:0' \
  'https://nexus.example.org:65536' 'https://nexus.example.org//nexus' \
  'https://nexus.example.org/nexus//' 'https://user@nexus.example.org' \
  'https://nexus.example.org?x=1' \
  "https://nexus.example.org"$'\n'"::warning::injected"; do
  merge_inputs fail "server '${server}' rejected" "${server}"
done
merge_inputs fail 'repository name with a slash' \
  'https://nexus.example.org' 'snap/shots'
merge_inputs fail 'username with a space' \
  'https://nexus.example.org' snapshots 'de ployer'

echo 'Merge lane: the branch the checkouts build'
# Resolve gerrit_branch "$3", ref "$4" and triggering ref "$5" for
# target repository "$6" and compare the verdict with "$1" and, on a
# pass, the branch with "$7"; "$2" labels the case.
merge_ref() {
  expect "$1" "$2" "${validate}" 'NEXUS_SERVER=https://nexus.example.org' \
    'REPOSITORY_NAME=snapshots' 'NEXUS_USERNAME=' \
    "GERRIT_BRANCH=$3" "BRANCH_INPUT=$4" "TRIGGER_REF=$5" \
    "TARGET_REPOSITORY=$6" 'CALLER_REPOSITORY=example-org/example-repo'
  if [ "$1" = pass ]; then
    expect_output "$2" checkout_ref "$7"
  fi
}
self='example-org/example-repo'
merge_ref pass 'triggering branch' '' '' refs/heads/main "${self}" \
  refs/heads/main
merge_ref pass 'repository named in another case' '' '' \
  refs/heads/main 'Example-Org/Example-Repo' refs/heads/main
merge_ref pass 'gerrit_branch over the trigger' 'stable/x' 'other' \
  refs/tags/v1 "${self}" refs/heads/stable/x
merge_ref pass 'ref as a name' '' 'stable/x' refs/tags/v1 "${self}" \
  refs/heads/stable/x
merge_ref pass 'ref as a branch ref' '' 'refs/heads/main' \
  refs/pull/1/merge "${self}" refs/heads/main
merge_ref pass 'another repository: its default branch' '' '' \
  refs/pull/1/merge 'example-org/fixture' ''
for trigger in refs/tags/v1.0.0 refs/pull/1/merge ''; do
  merge_ref fail "triggering ref '${trigger}' rejected" '' '' \
    "${trigger}" "${self}"
done
merge_ref fail 'gerrit_branch with a space' 'stable x' '' \
  refs/heads/main "${self}"
for ref in refs/tags/v1.0.0 refs/pull/1/head \
  0123456789abcdef0123456789abcdef01234567 'a..b' 'a b' 'main.lock' \
  "main"$'\n'"::warning::injected"; do
  merge_ref fail "ref '${ref}' rejected" '' "${ref}" refs/heads/main \
    "${self}"
done
# The loop's last case carries the line break.
if grep -q '^::warning::' "${tmp}/log"; then
  fail 'Branch validation let a line break start a workflow command'
fi

# maven-build-action expands workspace placeholders in mvn-opts and
# mvn-params; the merge lane repeats the expansion for the fetch and
# the SBOM. Its function must stay the pinned action's: the vendored
# copy is that action's script at the SHA below, and moving the pin
# without refreshing the copy fails here.
echo 'Merge lane: placeholder expansion matches maven-build-action'
expand_pin='c234ca4021cf69e1f993c054690fde436ae5316c'
expand_vendored='.github/scripts/vendor/maven-build-action/expand-workspace-vars.sh'
pins="$(grep -o 'lfreleng-actions/maven-build-action@[0-9a-f]*' "${merge}" \
  | sort -u)"
if [ "${pins}" != "lfreleng-actions/maven-build-action@${expand_pin}" ]; then
  fail "${merge}: maven-build-action is not pinned to ${expand_pin};" \
    "refresh ${expand_vendored} from the new pin and update expand_pin"
fi
expand="${tmp}/expand.sh"
extract "${merge}" build 'Expand workspace placeholders' "${expand}"
# The function definition, from its opening line to its closing brace.
function_of() {
  sed -n '/^ *expand_workspace_vars() {$/,/^ *}$/p' "$1" | sed 's/^ *//'
}
function_of "${expand_vendored}" > "${tmp}/expand-vendored"
function_of "${expand}" > "${tmp}/expand-merge"
if [ ! -s "${tmp}/expand-vendored" ] \
  || ! cmp -s "${tmp}/expand-vendored" "${tmp}/expand-merge"; then
  fail "${merge}: 'Expand workspace placeholders' differs from" \
    "${expand_vendored}"
fi
# Read output "$1" of the last expect() run, written in the
# name<<delimiter form.
heredoc_output() {
  awk -v name="$1" '
    !open && index($0, name "<<") == 1 {
      delim = substr($0, length(name) + 3); open = 1; next
    }
    open && $0 == delim { exit }
    open { print }' "${tmp}/output"
}
# shellcheck disable=SC2016
expect pass 'placeholder expansion' "${expand}" \
  'MVN_OPTS=-Dw=${GITHUB_WORKSPACE}/x -Dos=$RUNNER_OS' \
  'MVN_PARAMS=-Dh=${HOME} -Db=${project.basedir} $(id) $1'$'\n''-Dz' \
  'GITHUB_WORKSPACE=/ws' 'RUNNER_OS=Linux' 'HOME=/home/x'
# shellcheck disable=SC2016
if [ "$(heredoc_output mvn_opts)" != '-Dw=/ws/x -Dos=Linux' ] \
  || [ "$(heredoc_output mvn_params)" \
    != '-Dh=${HOME} -Db=${project.basedir} $(id) $1'$'\n''-Dz' ]; then
  fail 'placeholder expansion: unexpected output'
  sed 's/^/  | /' "${tmp}/output"
fi

echo 'Merge lane: m2repo absent before the fetch'
clean="${tmp}/clean.sh"
extract "${merge}" build 'Require a clean m2repo' "${clean}"
mkdir -p "${tmp}/workspace"
expect pass 'workspace without an m2repo' "${clean}" \
  "GITHUB_WORKSPACE=${tmp}/workspace"
mkdir -p "${tmp}/workspace/m2repo"
expect fail 'workspace with an m2repo' "${clean}" \
  "GITHUB_WORKSPACE=${tmp}/workspace"

echo 'Merge lane: the deploy landed in the m2repo'
landed="${tmp}/landed.sh"
extract "${merge}" build 'Check the deploy landed in the m2repo' "${landed}"
# Build m2repo "$1" holding the relative paths that follow.
m2repo() {
  local root="${tmp}/$1" file
  shift
  mkdir -p "${root}"
  for file in "$@"; do
    mkdir -p "${root}/${file%/*}"
    : > "${root}/${file}"
  done
}
version='org/example/core/1.0.0-SNAPSHOT'
m2repo valid "${version}/core-1.0.0-20260101.000000-1.jar" \
  "${version}/core-1.0.0-20260101.000000-1.jar.sha1" \
  "${version}/maven-metadata.xml" 'org/example/core/maven-metadata.xml'
m2repo metadata-only "${version}/maven-metadata.xml" \
  "${version}/maven-metadata.xml.sha1"
m2repo outside "${version}/core-1.0.0-20260101.000000-1.jar" \
  'org/examples/core/1.0.0-SNAPSHOT/core-1.0.0-20260101.000000-1.jar'
m2repo release "${version}/core-1.0.0-20260101.000000-1.jar" \
  'org/example/api/1.0.0/api-1.0.0.jar' \
  'org/example/api/maven-metadata.xml'
expect pass 'deployed tree' "${landed}" \
  "M2REPO_PATH=${tmp}/valid" 'GROUP_PATHS=org/example'
expect_output 'deployed tree' file_count 4
expect pass 'deployed tree, second group path' "${landed}" \
  "M2REPO_PATH=${tmp}/valid" 'GROUP_PATHS=com/other org/example'
expect fail 'metadata and checksums only' "${landed}" \
  "M2REPO_PATH=${tmp}/metadata-only" 'GROUP_PATHS=org/example'
expect fail 'a file outside the group paths' "${landed}" \
  "M2REPO_PATH=${tmp}/outside" 'GROUP_PATHS=org/example'
expect fail 'a release artefact beside a SNAPSHOT' "${landed}" \
  "M2REPO_PATH=${tmp}/release" 'GROUP_PATHS=org/example'
expect fail 'no group paths' "${landed}" \
  "M2REPO_PATH=${tmp}/valid" 'GROUP_PATHS='
expect fail 'no m2repo' "${landed}" \
  "M2REPO_PATH=${tmp}/absent" 'GROUP_PATHS=org/example'
# A link to a release directory outside the tree, beside a valid
# SNAPSHOT: find -type f skips it, but the upload would follow it.
m2repo linked "${version}/core-1.0.0-20260101.000000-1.jar" \
  'org/example/api/maven-metadata.xml'
mkdir -p "${tmp}/release-dir"
: > "${tmp}/release-dir/api-1.0.jar"
ln -s "${tmp}/release-dir" "${tmp}/linked/org/example/api/1.0"
expect fail 'a symbolic link to a directory' "${landed}" \
  "M2REPO_PATH=${tmp}/linked" 'GROUP_PATHS=org/example'
m2repo file-link "${version}/core-1.0.0-20260101.000000-1.jar"
ln -s core-1.0.0-20260101.000000-1.jar \
  "${tmp}/file-link/${version}/core-1.0.0-20260101.000000-2.jar"
expect fail 'a symbolic link to a file' "${landed}" \
  "M2REPO_PATH=${tmp}/file-link" 'GROUP_PATHS=org/example'
ln -s valid "${tmp}/root-link"
expect fail 'an m2repo that is itself a link' "${landed}" \
  "M2REPO_PATH=${tmp}/root-link" 'GROUP_PATHS=org/example'

echo 'Checkouts: submodule wiring'
for workflow in "${maven}" "${gradle}" "${merge}"; do
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
  # The merge lane builds the branch head and has no Gerrit checkout.
  followers="$(yq -o=json '.' "${workflow}" | jq -r '.jobs[] | .steps
    | . as $steps | to_entries[]
    | select((.value.uses // "")
      | test("^lfreleng-actions/checkout-gerrit-change-action@"))
    | ($steps[.key + 1].name // "none")')"
  while IFS= read -r follower; do
    if [ -n "${follower}" ] && [ "${follower}" != "${init_step}" ]; then
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
