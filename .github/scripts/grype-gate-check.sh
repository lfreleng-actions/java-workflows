#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Checks the Grype gate policy wiring of both verify lanes, which the
# fixtures cannot exercise without a change to their dependency files:
#
# - the six grype_* policy inputs exist with the agreed defaults, and
#   each reaches grype-scan-action under its own name, with the
#   sidecar path and at the pin the lanes share;
# - gerrit-validate's input check accepts each allowed value and
#   rejects a typo, run as extracted from the workflows;
# - the detection step runs dependency-change-action at its pin in a
#   dependency-change job of its own, which runs nothing from the
#   project, with the lane's preset and extra patterns over the whole
#   repository, after the checkout and before the sidecar upload; the
#   job, not the step, runs only under grype_gate_when:
#   dependencies-changed with the SBOM on, so any other call skips it
#   and the Grype job waits for nothing but the build;
# - that job's actions/checkout holds the parent of HEAD, without
#   which every pull request would be unresolved and gate;
# - the sidecar travels in an artefact of its own, uploaded only when
#   written, and no artefact the build job writes carries one;
# - the Grype job downloads the SBOM and the sidecar each by its
#   upload's ID, each into a directory of its own, and reads both from
#   there, so no artefact uploaded under a reused name, and nothing
#   inside the SBOM artefact, can pass for either;
# - the lanes publish the gate's verdict, and testing.yaml runs the
#   unresolved path against a pinned fixture and the resolved path
#   against this repository's fixtures, each read by a check job;
# - no symbolic link or submodule sits in this repository's tree,
#   without which the resolved lanes could report unresolved;
# - testing.yaml's gate-verdict-cases job runs dependency-change-action
#   and grype-scan-action at the lanes' pins with the lanes' own
#   inputs, on a known change per lane and case, with the verdict each
#   case expects fixed in the matrix.
#
# Run from the repository root: bash .github/scripts/grype-gate-check.sh

set -euo pipefail

maven='.github/workflows/maven-build-test.yaml'
gradle='.github/workflows/gradle-build-test.yaml'
testing='.github/workflows/testing.yaml'

detect_pin='257928b15e4e6a5cc5a888435be59b058055c4e1'
detect_uses="lfreleng-actions/dependency-change-action@${detect_pin}  # v0.0.1"
grype_pin='5c81b23afb2ea771b2d247807a12d90783328675'
detect_job='dependency-change'
# The condition on the detection job, as the literal workflow text.
detect_if="inputs.sbom_enabled && inputs.grype_enabled && inputs.grype_gate_when == 'dependencies-changed'"
detect_step='Detect dependency changes'
upload_step='Upload dependency-change sidecar'
download_step='Download dependency-change sidecar'
sbom_upload_step='Upload SBOM artifacts'
sbom_download_step='Download SBOM artefact'
grype_step='Grype audit SBOM'
validate_step='Validate Grype gate inputs'
sidecar='dependency-change.json'
# Where each download lands, and where the audit step reads each file.
sidecar_dir='dependency-change'
sbom_dir='sbom'
cases_job='gate-verdict-cases'

status=0
fail() {
  echo "::error::$*"
  status=1
}

tmp="$(mktemp -d)"
trap 'rm -rf -- "${tmp}"' EXIT

# Print field "$3" of step "$2" in job "$1" of workflow "$4", or nothing.
step_field() {
  JOB="$1" STEP="$2" FIELD="$3" yq -r '.jobs | to_entries | .[]
    | select(.key == strenv(JOB)) | .value.steps[]
    | select(.name == strenv(STEP)) | eval(strenv(FIELD)) // ""' "$4"
}

# Print the index of step "$2" in job "$1" of workflow "$3", or -1.
step_index() {
  local found
  found="$(JOB="$1" STEP="$2" yq -r '.jobs | to_entries | .[]
    | select(.key == strenv(JOB)) | .value.steps | to_entries | .[]
    | select(.value.name == strenv(STEP)) | .key' "$3")"
  echo "${found:--1}"
}

# Run script "$3" with the VAR=value pairs that follow, and compare its
# verdict with "$1" (pass or fail); "$2" labels the case.
expect() {
  local want="$1" label="$2" script="$3" got='pass'
  shift 3
  if ! env "$@" bash "${script}" > "${tmp}/log" 2>&1; then
    got='fail'
  fi
  if [ "${got}" != "${want}" ]; then
    fail "${label}: expected ${want}, got ${got}"
    sed 's/^/  | /' "${tmp}/log"
  fi
}

# name|type|default|grype-scan-action input, as the issue settled them.
inputs='grype_gate_when|string|always|gate-when
grype_dependency_policy|string|declared|dependency-policy
grype_transitive_fail_on|string|critical|transitive-fail-on
grype_only_fixed|boolean|true|only-fixed
grype_remediation_window_days|string||remediation-window-days
grype_remediation_window_start|string||remediation-window-start'

for pair in "${maven}:maven" "${gradle}:gradle"; do
  workflow="${pair%%:*}"
  preset="${pair##*:}"
  echo "${workflow}: Grype gate policy"

  while IFS='|' read -r name type default passed; do
    got_type="$(NAME="${name}" yq -r \
      '.on.workflow_call.inputs[strenv(NAME)].type // ""' "${workflow}")"
    got_default="$(NAME="${name}" yq -r \
      '.on.workflow_call.inputs[strenv(NAME)].default // ""' "${workflow}")"
    if [ "${got_type}" != "${type}" ] || [ "${got_default}" != "${default}" ]
    then
      fail "${workflow}: input ${name} must be a ${type} defaulting to" \
        "'${default}'; found ${got_type:-none} '${got_default}'"
    fi
    # The literal expression, not a shell expansion.
    want="\${{ inputs.${name} }}"
    got="$(step_field grype "${grype_step}" ".with[\"${passed}\"]" \
      "${workflow}")"
    if [ "${got}" != "${want}" ]; then
      fail "${workflow}: '${grype_step}' passes '${got}' as ${passed}," \
        "not ${want}"
    fi
  done <<< "${inputs}"

  manifest="$(step_field grype "${grype_step}" \
    '.with["dependency-change-manifest"]' "${workflow}")"
  if [ "${manifest}" != "${sidecar_dir}/${sidecar}" ]; then
    fail "${workflow}: '${grype_step}' reads '${manifest}' as the" \
      "dependency-change manifest, not ${sidecar_dir}/${sidecar}"
  fi
  sbom="$(step_field grype "${grype_step}" '.with.sbom' "${workflow}")"
  if [ "${sbom}" != "${sbom_dir}/sbom-cyclonedx.json" ]; then
    fail "${workflow}: '${grype_step}' scans '${sbom}', not" \
      "${sbom_dir}/sbom-cyclonedx.json"
  fi
  grype_uses="$(step_field grype "${grype_step}" '.uses' "${workflow}")"
  if [ "${grype_uses}" != "lfreleng-actions/grype-scan-action@${grype_pin}" ]
  then
    fail "${workflow}: '${grype_step}' runs '${grype_uses}', not" \
      "grype-scan-action at ${grype_pin}"
  fi

  echo "${workflow}: gate input validation"
  validate="${tmp}/${preset}-validate.sh"
  step_field gerrit-validate "${validate_step}" '.run' "${workflow}" \
    > "${validate}"
  if [ ! -s "${validate}" ]; then
    fail "${workflow}: gerrit-validate has no '${validate_step}' step"
    continue
  fi
  if [ -n "$(step_field gerrit-validate "${validate_step}" '.if' \
    "${workflow}")" ]; then
    fail "${workflow}: '${validate_step}' must run on every call"
  fi
  # Each case names one input's value; the rest hold their defaults.
  gate_inputs() {
    expect "$1" "${workflow}: $2" "${validate}" \
      "GATE_WHEN=${3-always}" "DEPENDENCY_POLICY=${4-declared}" \
      "TRANSITIVE_FAIL_ON=${5-critical}" "WINDOW_DAYS=${6-}" \
      "WINDOW_START=${7-}"
  }
  gate_inputs pass 'defaults'
  for value in always dependencies-changed; do
    gate_inputs pass "grype_gate_when '${value}'" "${value}"
  done
  for value in '' Always dependencies_changed never \
    $'always\n::warning::injected'; do
    gate_inputs fail "grype_gate_when '${value}' rejected" "${value}"
  done
  for value in all declared; do
    gate_inputs pass "grype_dependency_policy '${value}'" always "${value}"
  done
  for value in '' direct Declared 'all declared'; do
    gate_inputs fail "grype_dependency_policy '${value}' rejected" \
      always "${value}"
  done
  for value in none negligible low medium high critical; do
    gate_inputs pass "grype_transitive_fail_on '${value}'" always declared \
      "${value}"
  done
  for value in '' Critical moderate 'high,critical'; do
    gate_inputs fail "grype_transitive_fail_on '${value}' rejected" \
      always declared "${value}"
  done
  for value in '' 0 7 30 365; do
    gate_inputs pass "grype_remediation_window_days '${value}'" always \
      declared critical "${value}"
  done
  for value in -1 7.5 7d ' 7' 'seven'; do
    gate_inputs fail "grype_remediation_window_days '${value}' rejected" \
      always declared critical "${value}"
  done
  for value in '' 0001-01-01 2026-01-01 2024-02-29 2099-12-31; do
    gate_inputs pass "grype_remediation_window_start '${value}'" always \
      declared critical '' "${value}"
  done
  # 0000-01-01: GNU date accepts year zero, the action's ISO parser
  # does not, so it must fail here rather than after the build.
  for value in 2026-1-1 20260101 01-01-2026 2026-02-30 2026-13-01 \
    0000-01-01 0000-12-31 2026-01-01T00:00:00Z yesterday \
    $'2026-01-01\n::warning::injected'; do
    gate_inputs fail "grype_remediation_window_start '${value}' rejected" \
      always declared critical '' "${value}"
  done
  if grep -q '^::warning::' "${tmp}/log"; then
    fail "${workflow}: the gate validation let a line break start a" \
      'workflow command'
  fi

  echo "${workflow}: detection step"
  # The pin and its version comment, which yq would strip.
  if ! grep -qF "uses: ${detect_uses}" "${workflow}"; then
    fail "${workflow}: no step runs ${detect_uses}"
  fi
  if [ "$(grep -c 'lfreleng-actions/dependency-change-action@' \
    "${workflow}")" != '1' ]; then
    fail "${workflow}: dependency-change-action must appear once"
  fi
  detect_index="$(step_index "${detect_job}" "${detect_step}" "${workflow}")"
  if [ "${detect_index}" = '-1' ]; then
    fail "${workflow}: the ${detect_job} job has no '${detect_step}' step"
    continue
  fi
  uses="$(step_field "${detect_job}" "${detect_step}" '.uses' "${workflow}")"
  if [ "${uses}" != "${detect_uses%%  #*}" ]; then
    fail "${workflow}: '${detect_step}' runs '${uses}'"
  fi
  case "${preset}" in
    # A -D property in jvm.config can select a dependency version.
    maven) extra='.mvn/jvm.config' ;;
    # Any script file: a plugin or dependency declared in one the
    # preset does not name, such as a convention script a subproject
    # applies.
    gradle) extra=$'*.gradle\n*.gradle.kts' ;;
  esac
  for field in '.with.ecosystems' '.with.patterns' '.with.output' \
    '.with["path-prefix"]' '.with["gerrit-refspec"]' '.if'; do
    got="$(step_field "${detect_job}" "${detect_step}" "${field}" \
      "${workflow}")"
    # shellcheck disable=SC2016  # literal expression text, not shell
    case "${field}" in
      '.with.ecosystems') want="${preset}" ;;
      '.with.patterns') want="${extra}" ;;
      '.with.output') want="${sidecar}" ;;
      # Repository-wide: a Maven parent chain or a Gradle included
      # build crosses directory boundaries path_prefix cannot follow.
      '.with["path-prefix"]') want='.' ;;
      '.with["gerrit-refspec"]') want='${{ inputs.gerrit_refspec }}' ;;
      # The condition sits on the job; a step condition as well would
      # let the two drift apart.
      '.if') want='' ;;
    esac
    if [ "${got}" != "${want}" ]; then
      fail "${workflow}: '${detect_step}' has ${field} '${got}'," \
        "expected '${want}'"
    fi
  done
  # After every checkout, so HEAD is the change; before the upload,
  # so the sidecar is there to carry. Never in the build job, which
  # runs the project's own code.
  last_checkout="$(JOB="${detect_job}" yq -r '[.jobs[strenv(JOB)].steps
    | to_entries | .[]
    | select((.value.uses // "")
      | test("^(actions/checkout|lfreleng-actions/checkout-gerrit-change-action)@"))
    | .key] | max // -1' "${workflow}")"
  upload_index="$(step_index "${detect_job}" "${upload_step}" "${workflow}")"
  if [ "${last_checkout}" = '-1' ] || [ "${upload_index}" = '-1' ] \
    || [ "${detect_index}" -le "${last_checkout}" ] \
    || [ "${detect_index}" -ge "${upload_index}" ]; then
    fail "${workflow}: '${detect_step}' (step ${detect_index}) must" \
      "follow the last checkout (${last_checkout}) and precede" \
      "'${upload_step}' (${upload_index})"
  fi
  if [ "$(step_index build "${detect_step}" "${workflow}")" != '-1' ]; then
    fail "${workflow}: the build job must not run '${detect_step}'"
  fi
  if [ "$(step_index repository-metadata "${detect_step}" "${workflow}")" \
    != '-1' ]; then
    fail "${workflow}: repository-metadata must not run '${detect_step}':" \
      'the Grype job would then wait for it on every call'
  fi

  echo "${workflow}: the ${detect_job} job"
  # Only when a scan can consume the result: without the SBOM no Grype
  # job runs, and under 'always' the scan ignores the sidecar. On the
  # job, so every other call skips it outright and the Grype job's
  # wait for it ends at once.
  got="$(JOB="${detect_job}" yq -r '.jobs[strenv(JOB)].if // ""' \
    "${workflow}")"
  if [ "${got}" != "${detect_if}" ]; then
    fail "${workflow}: the ${detect_job} job runs if '${got}', expected" \
      "'${detect_if}'"
  fi
  # Nothing from the project: no build, SBOM or setup action, only the
  # runner hardening, the checkouts, the Gerrit submodule guard, the
  # detection and its upload.
  # shellcheck disable=SC2016  # yq expression, not shell
  stray="$(JOB="${detect_job}" yq -r '.jobs[strenv(JOB)].steps[]
    | select(((.uses // "") | test("^(lfreleng-actions/harden-runner-block-action|step-security/harden-runner|actions/checkout|lfreleng-actions/checkout-gerrit-change-action|lfreleng-actions/dependency-change-action|actions/upload-artifact)@") | not)
      and .name != "Initialise Gerrit change submodules")
    | .name' "${workflow}")"
  if [ -n "${stray}" ]; then
    fail "${workflow}: the ${detect_job} job runs other steps:" \
      "$(tr '\n' ',' <<< "${stray}")"
  fi

  echo "${workflow}: checkout depth"
  # The parent of HEAD is the base on a pull request: 2 holds it, as
  # does 0, the whole history; 1, or the default of 1, does not.
  depths="$(JOB="${detect_job}" yq -r '.jobs[strenv(JOB)].steps[]
    | select((.uses // "") | test("^actions/checkout@"))
    | .with["fetch-depth"] // "unset"' "${workflow}")"
  if [ -z "${depths}" ]; then
    fail "${workflow}: the ${detect_job} job has no actions/checkout step"
  fi
  while IFS= read -r depth; do
    case "${depth}" in
      0) ;;
      *[!0-9]* | '' | 1)
        fail "${workflow}: the ${detect_job} job's actions/checkout" \
          "fetches depth '${depth}'; dependency-change-action needs 2" \
          'or more' ;;
    esac
  done <<< "${depths}"

  echo "${workflow}: the sidecar travels in its own artefact"
  artefact="dependency-change-${preset}\${{ inputs.artifact_suffix }}"
  for field in '.if' '.with.name' '.with.path' '.with["if-no-files-found"]'
  do
    got="$(step_field "${detect_job}" "${upload_step}" "${field}" \
      "${workflow}")"
    case "${field}" in
      # On the action's manifest output, empty when unresolved: the
      # step then skips, rather than failing on a file that is not
      # there, and the job output below reads false.
      '.if') want="steps.dependency-change.outputs.manifest != ''" ;;
      '.with.name') want="${artefact}" ;;
      '.with.path') want="${sidecar}" ;;
      '.with["if-no-files-found"]') want='error' ;;
    esac
    if [ "${got}" != "${want}" ]; then
      fail "${workflow}: '${upload_step}' has ${field} '${got}'," \
        "expected '${want}'"
    fi
  done
  upload_id="$(step_field "${detect_job}" "${upload_step}" '.id' \
    "${workflow}")"
  # The ID of the upload, not a flag: the Grype job downloads by it,
  # so a same-name artefact from the build job cannot stand in.
  got="$(JOB="${detect_job}" yq -r \
    '.jobs[strenv(JOB)].outputs.dependency_change_artifact_id // ""' \
    "${workflow}")"
  if [ "${got}" != "\${{ steps.${upload_id:-?}.outputs.artifact-id }}" ]
  then
    fail "${workflow}: ${detect_job}'s dependency_change_artifact_id is" \
      "'${got}', not the artifact-id output of '${upload_step}'"
  fi
  if ! JOB="${detect_job}" yq -e \
    '.jobs.grype.needs | .. | select(. == strenv(JOB))' \
    "${workflow}" > /dev/null 2>&1; then
    fail "${workflow}: the grype job must need ${detect_job}"
  fi
  if yq -e '.jobs.grype.needs | .. | select(. == "repository-metadata")' \
    "${workflow}" > /dev/null 2>&1; then
    fail "${workflow}: the grype job must not need repository-metadata," \
      'which runs on every call'
  fi
  if ! yq -e '.jobs.grype.needs | .. | select(. == "build")' \
    "${workflow}" > /dev/null 2>&1; then
    fail "${workflow}: the grype job must still need build"
  fi
  # The SBOM too: the build job's upload publishes its ID, and the
  # Grype job downloads by it, so neither file the audit reads comes
  # from a name-based download.
  sbom_upload_id="$(step_field build "${sbom_upload_step}" '.id' \
    "${workflow}")"
  got="$(yq -r '.jobs.build.outputs.sbom_artifact_id // ""' "${workflow}")"
  if [ "${got}" != "\${{ steps.${sbom_upload_id:-?}.outputs.artifact-id }}" ]
  then
    fail "${workflow}: build's sbom_artifact_id is '${got}', not the" \
      "artifact-id output of '${sbom_upload_step}'"
  fi
  artifact_id="needs.${detect_job}.outputs.dependency_change_artifact_id"
  sbom_artifact_id='needs.build.outputs.sbom_artifact_id'
  for step in "${download_step}" "${sbom_download_step}"; do
    for field in '.if' '.with["artifact-ids"]' '.with["merge-multiple"]' \
      '.with.name' '.with.path'; do
      got="$(step_field grype "${step}" "${field}" "${workflow}")"
      if [ "${step}" = "${download_step}" ]; then
        case "${field}" in
          # Skipped when the dependency-change job uploaded nothing; an
          # ID that resolves to no artefact fails the download, and the
          # job.
          '.if') want="${artifact_id} != ''" ;;
          # By the exact upload, never by a name another job could
          # reuse.
          '.with["artifact-ids"]') want="\${{ ${artifact_id} }}" ;;
          # Into a directory of its own, so nothing the SBOM artefact
          # holds can pass for it, and with merge-multiple, which
          # drops the artefact-name level a download by ID adds.
          '.with["merge-multiple"]') want='true' ;;
          '.with.name') want='' ;;
          '.with.path') want="${sidecar_dir}" ;;
        esac
      else
        case "${field}" in
          # The grype job runs only when the SBOM uploaded, so the
          # download needs no condition of its own.
          '.if') want='' ;;
          '.with["artifact-ids"]') want="\${{ ${sbom_artifact_id} }}" ;;
          '.with["merge-multiple"]') want='true' ;;
          '.with.name') want='' ;;
          '.with.path') want="${sbom_dir}" ;;
        esac
      fi
      if [ "${got}" != "${want}" ]; then
        fail "${workflow}: '${step}' has ${field} '${got}'," \
          "expected '${want}'"
      fi
    done
    index="$(step_index grype "${step}" "${workflow}")"
    grype_index="$(step_index grype "${grype_step}" "${workflow}")"
    if [ "${index}" = '-1' ] || [ "${grype_index}" = '-1' ] \
      || [ "${index}" -ge "${grype_index}" ]; then
      fail "${workflow}: '${step}' must precede '${grype_step}'"
    fi
  done
  # No download in the grype job may resolve a name: the two above are
  # the only ones, and both go by ID.
  named="$(yq -r '.jobs.grype.steps[]
    | select((.uses // "") | test("^actions/download-artifact@"))
    | select(.with.name != null) | .name' "${workflow}")"
  if [ -n "${named}" ]; then
    fail "${workflow}: the grype job downloads by name in:" \
      "${named//$'\n'/, }"
  fi
  # No upload from the build job may carry it: the SBOM in particular,
  # whose job ran the project's build.
  carriers="$(SIDECAR="${sidecar}" UPLOAD="${upload_step}" yq -r '.jobs[]
    .steps[] | select((.uses // "") | test("^actions/upload-artifact@"))
    | select(.name != strenv(UPLOAD))
    | select((.with.path // "") | contains(strenv(SIDECAR))) | .name' \
    "${workflow}")"
  if [ -n "${carriers}" ]; then
    fail "${workflow}: ${sidecar} also travels in: ${carriers//$'\n'/, }"
  fi

  echo "${workflow}: gate verdict outputs"
  for triple in 'grype_gate_active:gate_active:gate-active' \
    'grype_gate_reason:gate_reason:gate-reason'; do
    IFS=':' read -r output job_output action_output <<< "${triple}"
    got="$(NAME="${output}" yq -r \
      '.on.workflow_call.outputs[strenv(NAME)].value // ""' "${workflow}")"
    if [ "${got}" != "\${{ jobs.grype.outputs.${job_output} }}" ]; then
      fail "${workflow}: output ${output} is '${got}', not the grype" \
        "job's ${job_output}"
    fi
    got="$(NAME="${job_output}" yq -r \
      '.jobs.grype.outputs[strenv(NAME)] // ""' "${workflow}")"
    if [ "${got}" != "\${{ steps.grype-audit.outputs.${action_output} }}" ]
    then
      fail "${workflow}: the grype job's ${job_output} is '${got}', not" \
        "the action's ${action_output}"
    fi
  done
done

# The behavioural half. The unresolved path: a lane running under the
# policy against a fixture at a pinned commit, whose HEAD is not the
# run's own commit, so the detector reports unresolved and the gate
# stays armed. The resolved path: each verify workflow building a
# fixture of this repository, at the run's own commit, so the detector
# writes a sidecar the check job holds the gate to. Each lane's check
# job reads the verdict the lane publishes.
echo "${testing}: lanes run under the policy"
policy_lanes='.jobs | to_entries | .[]
  | select((.value.uses // "") | test("/(maven|gradle)-build-test\\.yaml$"))
  | select(.value.with.grype_gate_when == "dependencies-changed")
  | select(.value.with.grype_enabled != false)
  | select(.value.with.sbom_enabled != false)'
lanes="$(yq -r "${policy_lanes}"'
  | select((.value.with.ref // "") | test("^[0-9a-f]{40}$"))
  | .key' "${testing}")"
if [ -z "${lanes}" ]; then
  fail "${testing}: no lane calls a verify workflow with grype_gate_when:" \
    "dependencies-changed, Grype and the SBOM on, and ref pinned to a" \
    'commit'
fi
resolved_lanes=''
for workflow in maven gradle; do
  resolved="$(WORKFLOW="${workflow}" yq -r "${policy_lanes}"'
    | select((.value.uses // "")
      | test("/" + strenv(WORKFLOW) + "-build-test\\.yaml$"))
    | select((.value.with.repository // "") == "")
    | select((.value.with.ref // "") == "")
    | select((.value.with.path_prefix // "")
      | test("^tests/fixtures/" + strenv(WORKFLOW) + "$"))
    | .key' "${testing}")"
  if [ -z "${resolved}" ]; then
    fail "${testing}: no lane calls ${workflow}-build-test.yaml under the" \
      "policy on this repository's tests/fixtures/${workflow}"
  fi
  lanes="${lanes}"$'\n'"${resolved}"
  resolved_lanes="${resolved_lanes}"$'\n'"${resolved}"
  # The fixture a resolved lane builds, with the file the preset
  # watches at its root.
  case "${workflow}" in
    maven) manifest="tests/fixtures/${workflow}/pom.xml" ;;
    gradle) manifest="tests/fixtures/${workflow}/settings.gradle.kts" ;;
  esac
  if [ ! -f "${manifest}" ]; then
    fail "no ${manifest}: the resolved ${workflow} lane has no fixture"
  fi
done
while IFS= read -r lane; do
  [ -n "${lane}" ] || continue
  readers="$(LANE="${lane}" yq -r '.jobs | to_entries | .[]
    | select(((.value.needs // []) | .. | select(tag == "!!str")
      | select(. == strenv(LANE))) | length > 0)
    | select((.value | tojson)
      | contains("needs." + strenv(LANE) + ".outputs.grype_gate_active"))
    | .key' "${testing}")"
  if [ -z "${readers}" ]; then
    fail "${testing}: no job needing ${lane} reads its grype_gate_active"
  fi
done <<< "${lanes}"

# The resolved lanes' check requires the sidecar artefact, on the
# strength of the detector's rules for a pull request of this
# repository: HEAD is the run's commit, the whole history holds the
# base, and nothing in the tree is a symbolic link or a submodule,
# which repository-wide detection would otherwise report unresolved.
echo 'the repository tree: no symbolic link or submodule'
entries="$(git ls-files -s | awk '$1 == "120000" || $1 == "160000" {print $4}')"
if [ -n "${entries}" ]; then
  fail 'the tree holds a symbolic link or submodule, which leaves the' \
    "resolved lanes' detection unresolved: ${entries//$'\n'/, }"
fi

# The fixed-expectation cases: the job needs both resolved lanes (for
# their SBOMs), runs the detector at the lanes' pin with the lanes'
# inputs over a scratch repository with an explicit base, and the
# scanner at the lanes' pin with the lanes' policy and manifest path;
# its matrix fixes each case's expected verdict.
echo "${testing}: ${cases_job}"
if ! yq -e ".jobs[\"${cases_job}\"]" "${testing}" > /dev/null 2>&1; then
  fail "${testing}: no ${cases_job} job"
else
  while IFS= read -r lane; do
    [ -n "${lane}" ] || continue
    if ! JOB="${cases_job}" LANE="${lane}" yq -e \
      '.jobs[strenv(JOB)].needs | .. | select(. == strenv(LANE))' \
      "${testing}" > /dev/null 2>&1; then
      fail "${testing}: ${cases_job} must need ${lane}"
    fi
  done <<< "${resolved_lanes}"
  if ! grep -qF "uses: ${detect_uses}" "${testing}"; then
    fail "${testing}: no step runs ${detect_uses}"
  fi
  # shellcheck disable=SC2016  # literal expression text, not shell
  for field in '.uses' '.with.ecosystems' '.with.patterns' '.with.base' \
    '.with.output' '.with["path-prefix"]'; do
    got="$(step_field "${cases_job}" "${detect_step}" "${field}" "${testing}")"
    case "${field}" in
      '.uses') want="${detect_uses%%  #*}" ;;
      '.with.ecosystems') want='${{ matrix.ecosystems }}' ;;
      '.with.patterns') want='${{ matrix.patterns }}' ;;
      '.with.base') want='${{ steps.scratch.outputs.base }}' ;;
      '.with.output') want="${sidecar}" ;;
      '.with["path-prefix"]') want='.' ;;
    esac
    if [ "${got}" != "${want}" ]; then
      fail "${testing}: ${cases_job}'s '${detect_step}' has ${field}" \
        "'${got}', expected '${want}'"
    fi
  done
  # The matrix rows carry each lane's preset and extra patterns, as
  # the lane's detection step passes them, and each case's verdict.
  for preset in maven gradle; do
    case "${preset}" in
      maven) extra='.mvn/jvm.config' ;;
      gradle) extra=$'*.gradle\n*.gradle.kts' ;;
    esac
    for field in ecosystems patterns; do
      got="$(JOB="${cases_job}" LANE="${preset}" FIELD="${field}" yq -r \
        '.jobs[strenv(JOB)].strategy.matrix.include[]
        | select(.lane == strenv(LANE)) | .[strenv(FIELD)] // ""' \
        "${testing}")"
      case "${field}" in
        ecosystems) want="${preset}" ;;
        patterns) want="${extra}" ;;
      esac
      if [ "${got}" != "${want}" ]; then
        fail "${testing}: ${cases_job}'s ${preset} row has ${field}" \
          "'${got}', expected '${want}'"
      fi
    done
  done
  for pair in 'unchanged:false' 'changed:true'; do
    got="$(JOB="${cases_job}" CASE="${pair%%:*}" yq -r \
      '.jobs[strenv(JOB)].strategy.matrix.include[]
      | select(.case == strenv(CASE)) | .expected // ""' "${testing}")"
    if [ "${got}" != "${pair##*:}" ]; then
      fail "${testing}: ${cases_job}'s ${pair%%:*} case expects" \
        "'${got}', not ${pair##*:}"
    fi
  done
  for field in lane case; do
    got="$(JOB="${cases_job}" FIELD="${field}" yq -r \
      '.jobs[strenv(JOB)].strategy.matrix[strenv(FIELD)] // [] | join(" ")' \
      "${testing}")"
    case "${field}" in
      lane) want='maven gradle' ;;
      case) want='unchanged changed' ;;
    esac
    if [ "${got}" != "${want}" ]; then
      fail "${testing}: ${cases_job}'s matrix.${field} is '${got}', not" \
        "'${want}'"
    fi
  done
  # The scanner, with the lanes' policy defaults as literal values.
  # shellcheck disable=SC2016  # literal expression text, not shell
  for field in '.uses' '.with["gate-when"]' \
    '.with["dependency-change-manifest"]' '.with["dependency-policy"]' \
    '.with["transitive-fail-on"]' '.with["only-fixed"]' '.with["fail-on"]'
  do
    got="$(step_field "${cases_job}" "${grype_step}" "${field}" "${testing}")"
    case "${field}" in
      '.uses') want="lfreleng-actions/grype-scan-action@${grype_pin}" ;;
      '.with["gate-when"]') want='dependencies-changed' ;;
      '.with["dependency-change-manifest"]') want="${sidecar}" ;;
      '.with["dependency-policy"]') want='declared' ;;
      '.with["transitive-fail-on"]') want='critical' ;;
      '.with["only-fixed"]') want='true' ;;
      '.with["fail-on"]') want='medium' ;;
    esac
    if [ "${got}" != "${want}" ]; then
      fail "${testing}: ${cases_job}'s '${grype_step}' has ${field}" \
        "'${got}', expected '${want}'"
    fi
  done
  for workflow in "${maven}" "${gradle}"; do
    got="$(yq -r '.on.workflow_call.inputs.grype_fail_on.default // ""' \
      "${workflow}")"
    if [ "${got}" != 'medium' ]; then
      fail "${workflow}: grype_fail_on defaults to '${got}', and" \
        "${cases_job} scans at medium"
    fi
  done
  if [ "$(step_index "${cases_job}" "${detect_step}" "${testing}")" -ge \
    "$(step_index "${cases_job}" "${grype_step}" "${testing}")" ]; then
    fail "${testing}: ${cases_job} must detect before it scans"
  fi
fi

if [ "${status}" -eq 0 ]; then
  echo 'Grype gate check passed ✅'
fi
exit "${status}"
