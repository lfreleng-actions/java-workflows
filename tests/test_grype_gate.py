# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Contract tests for the Grype gate policy wiring of the Maven lanes.

The fixtures cannot exercise this wiring without a change to their
dependency files, so these tests hold it in place:

- the six grype_* policy inputs exist with the agreed defaults, and
  each reaches grype-scan-action under its own name, at the pin the
  lanes share;
- each lane's validation job (gerrit-validate in the verify lanes,
  validate in the merge lane) validates the Grype inputs by running
  grype-scan-action in validate-only mode, at the scan's pin, with
  every input the scan passes as the lane's own or as a fixed value,
  as the same expression, and nothing to scan, in a job that fetches
  that one action and nothing else; the verify lanes'
  grype_dependency_ecosystems check accepts each allowed value and
  rejects a typo, run as extracted from the workflows;
- every repository-metadata-action call is at the v0.5.1 pin, and no
  workflow calls dependency-change-action directly, reads its
  sidecar, or keeps a dependency-change job;
- each verify lane's repository-metadata job detects with its own
  step, only under grype_gate_when: dependencies-changed with Grype
  and the SBOM on, over the whole repository, with every preset unless
  the caller narrows them, a narrowed selection always prefixed with
  the lane's own preset, and only the caller's extra patterns, after a
  checkout that holds the parent of HEAD, and publishes
  dependencies_changed as a job output;
- the Grype job needs build and repository-metadata, still runs when
  the metadata job failed or skipped, reads the verdict only when that
  job succeeded, downloads nothing but the SBOM, by its upload's ID,
  and publishes the verdict it read;
- the new detection, bypass and merge-lane policy inputs are declared
  with their defaults and passed through, and the merge scan still
  reports without gating;
- the lanes publish the gate's verdict, and testing.yaml runs the
  unresolved path against a pinned fixture and the resolved path
  against this repository's fixtures, each read by a check job;
- no symbolic link or submodule sits in this repository's tree,
  without which the resolved lanes could report unresolved;
- testing.yaml's gate-verdict-cases job runs repository-metadata-action
  and grype-scan-action at the lanes' pins with the lanes' own inputs,
  on a known change per lane and case, over every preset and over a
  selection narrowed to node that the lane's preset prefixes, with the
  verdict each case expects fixed in the matrix;
- testing.yaml's gate-validate-check job runs the validation step at
  the lanes' pin with the lanes' defaults and a gate-when the action
  does not know, as the lanes' job does, with no checkout and no
  harden-runner, and expects it to fail.

Each structural check is a method taking the workflow it judges; the
positive tests hand it the real workflows, the negative tests a copy
with one thing wrong, and expect it to fail.
"""

from __future__ import annotations

import copy
import re
import subprocess
import unittest
from typing import Any, ClassVar, cast
from unittest import mock

from guards import needs_runner_tools, run_script
from helpers import (
    CHECKOUT_ACTIONS,
    ECOSYSTEMS_VALIDATE,
    GATE_VALIDATE,
    GRADLE,
    MAVEN,
    MERGE,
    TESTING,
    ContractCase,
    Job,
    Step,
    Verdict,
    Workflow,
    is_action,
    job_of,
    jobs_of,
    load_workflow,
    needs_of,
    outputs_of,
    run_of,
    scalars,
    section,
    step_index,
    step_of,
    steps_of,
    text,
    uses_of,
    with_of,
)
from yaml_loading import ROOT, read_text

LANES = (MAVEN, GRADLE)
PRESETS = {MAVEN: "maven", GRADLE: "gradle"}

META_PIN = "f0e5d2d8dc1154a5d702b75acc551eff6ba072dc"
META_ACTION = "lfreleng-actions/repository-metadata-action"
META_USES = f"{META_ACTION}@{META_PIN}"
# The pin with its version comment, as the workflow text must hold it.
META_LINE = f"uses: {META_USES}  # v0.5.1"
# The detector the lanes called before repository-metadata-action took
# detection over; no workflow may call it, or read its sidecar, now.
OLD_DETECTOR = "lfreleng-actions/dependency-change-action@"
OLD_WIRING = (
    OLD_DETECTOR,
    "dependency-change.json",
    "dependency-change-manifest",
)
OLD_JOB = "dependency-change"
GRYPE_PIN = "f65dca2762823cfc8f376e32fee9baa6f3292696"
GRYPE_ACTION = "lfreleng-actions/grype-scan-action"
GRYPE_USES = f"{GRYPE_ACTION}@{GRYPE_PIN}"
# The pin with its version comment, as each lane's text must hold it:
# once on the validation step, once on the scan.
GRYPE_LINE = f"uses: {GRYPE_USES}  # v0.6.2"

VALIDATE_JOB = "gerrit-validate"
MERGE_VALIDATE_JOB = "validate"
# The scan's inputs that are one grype_* input of the lane, passed
# verbatim; the validation step must pass each with the same
# expression. Read from the scan step, so an input added there and
# not to the validator fails the suite; these must be among them.
POLICY_EXPRESSION = re.compile(r"^\$\{\{ inputs\.grype_[a-z_]+ \}\}$")
VALIDATED_INPUTS = frozenset(
    {
        "fail-on",
        "gate-when",
        "dependency-policy",
        "transitive-fail-on",
        "only-fixed",
        "remediation-window-days",
        "remediation-window-start",
        "bypass-repository",
    }
)
# The merge lane's scan has no gate and no window, and holds
# permit-fail at a fixed 'true', which the validator copies.
MERGE_VALIDATED_INPUTS = frozenset(
    {
        "fail-on",
        "permit-fail",
        "only-fixed",
        "dependency-policy",
        "transitive-fail-on",
        "bypass-repository",
    }
)
# What the scan scans; validate-only needs neither, and the validator
# passes neither.
TARGET_INPUTS = frozenset({"sbom", "target"})
# The one policy-adjacent input gerrit-validate still checks in shell:
# an input of repository-metadata-action, not of grype-scan-action.
ECOSYSTEMS_INPUT = "${{ inputs.grype_dependency_ecosystems }}"

META_JOB = "repository-metadata"
META_STEP = "Gather repository metadata"
META_STEP_ID = "repo-metadata"
# When the metadata step detects, as the literal workflow text.
DETECT_IF = (
    "inputs.sbom_enabled && inputs.grype_enabled"
    " && inputs.grype_gate_when == 'dependencies-changed'"
)
# The verdict as the Grype job reads it: empty unless the metadata
# job succeeded, since a failed job can still expose an output an
# earlier step wrote, and empty gates.
VERDICT = (
    "needs.repository-metadata.result == 'success'"
    " && needs.repository-metadata.outputs.dependencies_changed || ''"
)
GRYPE_IF = (
    "${{ !cancelled() && needs.build.outputs.sbom_uploaded == 'true'"
    " && inputs.grype_enabled }}"
)
DETECT_STEP = "Detect dependency changes"
SBOM_UPLOAD_STEP = "Upload SBOM artifacts"
SBOM_DOWNLOAD_STEP = "Download SBOM artefact"
GRYPE_STEP = "Grype audit SBOM"
# Where the SBOM download lands, and where the audit step reads it.
SBOM_DIR = "sbom"
CASES_JOB = "gate-verdict-cases"
CHECK_JOB = "gate-validate-check"
CHECK_ASSERT = "Assert the step rejected the gate-when"
GATE_WHEN_VALUES = ("always", "dependencies-changed")
SUFFIX = "${{ inputs.artifact_suffix }}"
MERGE_VALIDATE = "Validate Grype inputs"
# Each lane's validation job, the step in it that runs grype-scan-action
# in validate-only mode, and the scan inputs that must be among the
# ones it mirrors.
VALIDATORS: dict[str, tuple[str, str, frozenset[str]]] = {
    MAVEN: (VALIDATE_JOB, GATE_VALIDATE, VALIDATED_INPUTS),
    GRADLE: (VALIDATE_JOB, GATE_VALIDATE, VALIDATED_INPUTS),
    MERGE: (MERGE_VALIDATE_JOB, MERGE_VALIDATE, MERGE_VALIDATED_INPUTS),
}
VALIDATED_LANES = (MAVEN, GRADLE, MERGE)

# The presets cover each lane's own extra files (.mvn/jvm.config, every
# *.gradle and *.gradle.kts script), so a lane passes the caller's
# patterns alone.
CALLER_PATTERNS = "${{ inputs.grype_dependency_patterns }}"

# A file each lane's preset covers beside its build file, which the
# auxiliary case commits to prove the preset alone flags it.
AUXILIARY_FILES = {
    "maven": ".mvn/jvm.config",
    "gradle": "gradle/deps.gradle",
}
CASE_VERDICTS = {"unchanged": "false", "changed": "true", "auxiliary": "true"}


def lane_ecosystems(preset: str) -> str:
    """Return the lane's detection presets, as the literal workflow text.

    Empty selects every preset; a narrowed selection always includes
    the lane's own, which covers its build and auxiliary files.
    """
    return (
        "${{ inputs.grype_dependency_ecosystems != '' && format('"
        + preset
        + ",{0}', inputs.grype_dependency_ecosystems) || '' }}"
    )


# The cases job's detector presets: the lanes' expression over the
# matrix, so the narrowed cases hold the lanes' prefixing.
CASES_ECOSYSTEMS = (
    "${{ matrix.ecosystems != '' && format('{0},{1}', matrix.lane,"
    " matrix.ecosystems) || '' }}"
)
# Every preset, and a selection that names neither lane's preset.
CASES_ECOSYSTEM_AXIS = ["", "node"]

# name, type, default, grype-scan-action input, as the issue settled them.
POLICY_INPUTS = (
    ("grype_gate_when", "string", "always", "gate-when"),
    ("grype_dependency_policy", "string", "declared", "dependency-policy"),
    (
        "grype_transitive_fail_on",
        "string",
        "critical",
        "transitive-fail-on",
    ),
    ("grype_only_fixed", "boolean", "true", "only-fixed"),
    (
        "grype_remediation_window_days",
        "string",
        "",
        "remediation-window-days",
    ),
    (
        "grype_remediation_window_start",
        "string",
        "",
        "remediation-window-start",
    ),
)

# The verify lanes' bypass input: name, the job and step that receive
# it, and the input there. The ecosystems and patterns inputs are
# checked in MetadataDetection.
VERIFY_INPUTS = (
    ("grype_bypass_repository", "grype", GRYPE_STEP, "bypass-repository"),
)
NEW_VERIFY_INPUTS = (
    "grype_dependency_ecosystems",
    "grype_dependency_patterns",
    "grype_bypass_repository",
)

# The merge lane's policy inputs: name, type, default, grype-scan-action
# input. The defaults are the action's own, so the report is unchanged.
MERGE_INPUTS = (
    ("grype_fail_on", "string", "medium", "fail-on"),
    ("grype_only_fixed", "boolean", "false", "only-fixed"),
    ("grype_dependency_policy", "string", "all", "dependency-policy"),
    ("grype_transitive_fail_on", "string", "none", "transitive-fail-on"),
    ("grype_bypass_repository", "string", "", "bypass-repository"),
)

ECOSYSTEM_PASSES = (
    "",
    "maven",
    "gradle",
    "node,python,go,maven,gradle,rust,docker",
    "maven, gradle",
    " maven , gradle ",
)
ECOSYSTEM_FAILS = (
    "Maven",
    "java",
    "maven,",
    ",maven",
    "maven,,gradle",
    "maven gradle",
    "maven;gradle",
    "maven\ngradle",
    "maven\n::warning::injected",
)

COMMIT = re.compile(r"^[0-9a-f]{40}$")


def mutated(workflow: Workflow) -> Workflow:
    """Return a deep copy of ``workflow`` for a test to break."""
    return copy.deepcopy(workflow)


def call_inputs(workflow: Workflow) -> dict[str, Any]:
    """Return the ``workflow_call`` inputs of ``workflow``."""
    return section(section(section(workflow, "on"), "workflow_call"), "inputs")


def call_outputs(workflow: Workflow) -> dict[str, Any]:
    """Return the ``workflow_call`` outputs of ``workflow``."""
    return section(
        section(section(workflow, "on"), "workflow_call"), "outputs"
    )


def last_checkout(job: Job) -> int:
    """Return the index of the last checkout step of ``job``, or -1."""
    found = -1
    for index, step in enumerate(steps_of(job)):
        if is_action(step, *CHECKOUT_ACTIONS):
            found = index
    return found


def needs_mention(job: Job, name: str) -> bool:
    """Return whether ``name`` is anywhere under the job's ``needs``."""
    return name in [text(value) for value in scalars(job.get("needs"))]


class GatePolicyInputs(ContractCase):
    """The six policy inputs and how the scanner receives them."""

    def check_inputs(self, workflow: Workflow) -> None:
        """Fail unless each input is as agreed and reaches the scanner."""
        inputs = call_inputs(workflow)
        grype = step_of(job_of(workflow, "grype"), GRYPE_STEP)
        passed = with_of(grype)
        for name, kind, default, target in POLICY_INPUTS:
            declared = section(inputs, name)
            self.assertEqual(
                (text(declared.get("type")), text(declared.get("default"))),
                (kind, default),
                f"input {name} must be a {kind} defaulting to '{default}'",
            )
            self.assertEqual(
                text(passed.get(target)),
                f"${{{{ inputs.{name} }}}}",
                f"'{GRYPE_STEP}' must pass inputs.{name} as {target}",
            )

    def check_scanner(self, workflow: Workflow) -> None:
        """Fail unless the scanner is pinned and reads the SBOM in place."""
        grype = step_of(job_of(workflow, "grype"), GRYPE_STEP)
        passed = with_of(grype)
        self.assertEqual(
            text(passed.get("sbom")),
            f"{SBOM_DIR}/sbom-cyclonedx.json",
            f"'{GRYPE_STEP}' must scan the SBOM from its download",
        )
        self.assertEqual(
            uses_of(grype),
            GRYPE_USES,
            f"'{GRYPE_STEP}' must run grype-scan-action at {GRYPE_PIN}",
        )

    def test_inputs_reach_the_scanner(self) -> None:
        """Each lane declares the six inputs and passes each through."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_inputs(load_workflow(lane))

    def test_the_scanner_is_pinned_and_reads_the_download(self) -> None:
        """Each lane's scanner is at the shared pin over the SBOM."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_scanner(load_workflow(lane))

    def test_a_changed_default_fails(self) -> None:
        """A policy input with another default fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        call_inputs(workflow)["grype_gate_when"]["default"] = (
            "dependencies-changed"
        )
        self.assert_check_fails(self.check_inputs, workflow)

    def test_a_missing_input_fails(self) -> None:
        """A lane without one of the six inputs fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        del call_inputs(workflow)["grype_only_fixed"]
        self.assert_check_fails(self.check_inputs, workflow)

    def test_an_input_passed_under_another_name_fails(self) -> None:
        """An input the scanner receives under another name fails."""
        workflow = mutated(load_workflow(MAVEN))
        passed = with_of(step_of(job_of(workflow, "grype"), GRYPE_STEP))
        passed["gate-when"], passed["dependency-policy"] = (
            passed["dependency-policy"],
            passed["gate-when"],
        )
        self.assert_check_fails(self.check_inputs, workflow)

    def test_a_scanner_at_another_pin_fails(self) -> None:
        """A scanner at another commit fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        step = step_of(job_of(workflow, "grype"), GRYPE_STEP)
        step["uses"] = f"lfreleng-actions/grype-scan-action@{'0' * 40}"
        self.assert_check_fails(self.check_scanner, workflow)

    def test_an_sbom_read_from_elsewhere_fails(self) -> None:
        """A scanner reading the SBOM from the workspace root fails."""
        workflow = mutated(load_workflow(MAVEN))
        step = step_of(job_of(workflow, "grype"), GRYPE_STEP)
        with_of(step)["sbom"] = "sbom-cyclonedx.json"
        self.assert_check_fails(self.check_scanner, workflow)


def policy_inputs(step: Step) -> dict[str, str]:
    """Return the inputs ``step`` passes as one grype_* input, verbatim."""
    return {
        name: text(value)
        for name, value in with_of(step).items()
        if POLICY_EXPRESSION.match(text(value)) is not None
    }


def mirrored_inputs(scan: Step) -> dict[str, str]:
    """Return the scan's inputs the validation step must pass, verbatim.

    Each input the scan passes as one grype_* input of the lane, or as
    a fixed value with no expression in it, less the scan target. An
    input built from another context (the token, the artefact name, the
    metadata job's verdict) is the scan's alone: validate-only reads no
    bypass issue and uploads nothing.
    """
    return {
        name: text(value)
        for name, value in with_of(scan).items()
        if name not in TARGET_INPUTS
        and (
            POLICY_EXPRESSION.match(text(value)) is not None
            or "${{" not in text(value)
        )
    }


def uses_in(job: Job) -> list[str]:
    """Return the ``uses:`` of each action step of ``job``, in order."""
    return [uses_of(step) for step in steps_of(job) if uses_of(step)]


def validate_job_of(workflow: Workflow, lane: str) -> Job:
    """Return the validation job of ``workflow``, the one ``lane`` has."""
    return job_of(workflow, VALIDATORS[lane][0])


def validator_of(workflow: Workflow, lane: str) -> Step:
    """Return the validate-only step of ``workflow``, as ``lane`` names it."""
    return step_of(validate_job_of(workflow, lane), VALIDATORS[lane][1])


class GateInputValidation(ContractCase):
    """The Grype input validation: grype-scan-action in validate-only mode.

    Each lane's validation job runs the action at the scan's pin with
    ``validate-only: 'true'`` and every input the grype job's scan
    passes as a plain expression of the lane's inputs or as a fixed
    value, each the same, and nothing else: no ``sbom``, no ``target``.
    The rules are then the action's own, and the two steps cannot
    drift. The job fetches that one action and nothing else: no
    checkout and no harden-runner, since validate-only makes no
    network request. In the verify lanes,
    ``grype_dependency_ecosystems`` stays a shell check, run here as
    extracted, as an input of repository-metadata-action.
    """

    def check_validator(self, workflow: Workflow, lane: str) -> None:
        """Fail unless the validator mirrors the scan in validate-only mode."""
        validator = validator_of(workflow, lane)
        scan = step_of(job_of(workflow, "grype"), GRYPE_STEP)
        mirrored = mirrored_inputs(scan)
        name = VALIDATORS[lane][1]
        self.assertLessEqual(
            VALIDATORS[lane][2],
            set(mirrored),
            f"'{GRYPE_STEP}' must pass each policy input as the lane's own",
        )
        self.assertEqual(
            uses_of(validator),
            uses_of(scan),
            f"'{name}' and '{GRYPE_STEP}' must share one pin",
        )
        self.assertEqual(
            uses_of(validator),
            GRYPE_USES,
            f"'{name}' must run grype-scan-action at {GRYPE_PIN}",
        )
        self.assertEqual(
            with_of(validator),
            {"validate-only": "true", **mirrored},
            f"'{name}' must pass validate-only 'true' and the scan's"
            " expressions and fixed values, and nothing else",
        )

    def check_job_fetches_one_action(
        self, workflow: Workflow, lane: str
    ) -> None:
        """Fail unless the validator is the job's only action step."""
        self.assertEqual(
            uses_in(validate_job_of(workflow, lane)),
            [GRYPE_USES],
            f"{VALIDATORS[lane][0]} must run no action but the validator:"
            " no checkout, no harden-runner",
        )

    def check_no_shell_validator(self, workflow: Workflow, lane: str) -> None:
        """Fail unless no run: step reads a grype_* input but ecosystems."""
        for step in steps_of(validate_job_of(workflow, lane)):
            if not step.get("run"):
                continue
            read = [
                text(value)
                for value in scalars(step.get("env"))
                if "inputs.grype_" in text(value)
            ]
            self.assertEqual(
                read,
                [ECOSYSTEMS_INPUT]
                if step.get("name") == ECOSYSTEMS_VALIDATE
                else [],
                f"{VALIDATORS[lane][0]}: '{text(step.get('name'))}' must"
                " not check a grype_* policy input in shell",
            )

    def check_ecosystems_step(self, workflow: Workflow) -> None:
        """Fail unless the ecosystems check reads that input alone."""
        step = step_of(job_of(workflow, VALIDATE_JOB), ECOSYSTEMS_VALIDATE)
        self.assertEqual(
            section(step, "env"),
            {"ECOSYSTEMS": ECOSYSTEMS_INPUT},
            f"'{ECOSYSTEMS_VALIDATE}' must read grype_dependency_ecosystems",
        )

    def check_pin_text(self, content: str, path: str) -> None:
        """Fail unless the pinned line appears twice, and no other ref."""
        self.assertEqual(
            content.count(GRYPE_LINE),
            2,
            f"{path}: the validation step and the scan must both run"
            f" {GRYPE_LINE}",
        )
        self.assertEqual(
            content.count(f"{GRYPE_ACTION}@"),
            2,
            f"{path}: grype-scan-action must appear at that pin alone",
        )

    def validate(self, lane: str, ecosystems: str) -> Verdict:
        """Run the lane's ecosystems check, as extracted, with one value."""
        script = run_of(load_workflow(lane), VALIDATE_JOB, ECOSYSTEMS_VALIDATE)
        return run_script(script, {"ECOSYSTEMS": ecosystems})

    def test_the_steps_run_on_every_call(self) -> None:
        """No validation step has a condition."""
        for lane in VALIDATED_LANES:
            names = [VALIDATORS[lane][1]]
            if lane in LANES:
                names.append(ECOSYSTEMS_VALIDATE)
            for name in names:
                with self.subTest(lane=lane, step=name):
                    step = step_of(
                        validate_job_of(load_workflow(lane), lane), name
                    )
                    self.assertEqual(
                        text(step.get("if")),
                        "",
                        f"{lane}: '{name}' must run on every call",
                    )

    def test_the_validator_mirrors_the_scan(self) -> None:
        """Each lane validates through the action with the scan's inputs."""
        for lane in VALIDATED_LANES:
            with self.subTest(lane=lane):
                self.check_validator(load_workflow(lane), lane)

    def test_the_job_fetches_one_action(self) -> None:
        """Each lane's validation job runs no action but the validator."""
        for lane in VALIDATED_LANES:
            with self.subTest(lane=lane):
                self.check_job_fetches_one_action(load_workflow(lane), lane)

    def test_no_shell_validator_remains(self) -> None:
        """No run: step of a validation job checks a policy input."""
        for lane in VALIDATED_LANES:
            with self.subTest(lane=lane):
                self.check_no_shell_validator(load_workflow(lane), lane)

    def test_the_ecosystems_step_reads_its_input(self) -> None:
        """The ecosystems check reads grype_dependency_ecosystems alone."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_ecosystems_step(load_workflow(lane))

    def test_the_pin_appears_twice_with_its_comment(self) -> None:
        """Each lane's text holds the pinned uses: line twice."""
        for lane in VALIDATED_LANES:
            with self.subTest(lane=lane):
                self.check_pin_text(read_text(lane), lane)

    @needs_runner_tools
    def test_dependency_ecosystems(self) -> None:
        """grype_dependency_ecosystems takes known presets, or nothing."""
        for lane in LANES:
            for value in ECOSYSTEM_PASSES:
                with self.subTest(lane=lane, value=value):
                    self.assert_passes(
                        self.validate(lane, value),
                        f"grype_dependency_ecosystems '{value}'",
                    )
            for value in ECOSYSTEM_FAILS:
                with self.subTest(lane=lane, value=value):
                    self.assert_fails(
                        self.validate(lane, value),
                        f"grype_dependency_ecosystems '{value}' rejected",
                    )

    @needs_runner_tools
    def test_no_line_break_starts_a_workflow_command(self) -> None:
        """An injected line break never reaches the log as a command."""
        for lane in LANES:
            with self.subTest(lane=lane):
                verdict = self.validate(lane, "maven\n::warning::injected")
                self.assert_fails(verdict, "ecosystems with a line break")
                self.assertFalse(
                    verdict.warned(),
                    f"{lane}: the ecosystems check let a line break start"
                    " a workflow command",
                )

    def test_a_drifted_expression_fails(self) -> None:
        """A validator passing gate-when from another input fails."""
        workflow = mutated(load_workflow(MAVEN))
        validator = validator_of(workflow, MAVEN)
        with_of(validator)["gate-when"] = (
            "${{ inputs.grype_dependency_policy }}"
        )
        self.assert_check_fails(self.check_validator, workflow, MAVEN)

    def test_a_drifted_merge_expression_fails(self) -> None:
        """A merge validator passing fail-on from another input fails."""
        workflow = mutated(load_workflow(MERGE))
        validator = validator_of(workflow, MERGE)
        with_of(validator)["fail-on"] = (
            "${{ inputs.grype_transitive_fail_on }}"
        )
        self.assert_check_fails(self.check_validator, workflow, MERGE)

    def test_a_missing_validate_only_fails(self) -> None:
        """A validator without validate-only, a real scan, fails."""
        workflow = mutated(load_workflow(GRADLE))
        validator = validator_of(workflow, GRADLE)
        del with_of(validator)["validate-only"]
        self.assert_check_fails(self.check_validator, workflow, GRADLE)

    def test_a_merge_validator_without_validate_only_fails(self) -> None:
        """A merge validator without validate-only, a real scan, fails."""
        workflow = mutated(load_workflow(MERGE))
        validator = validator_of(workflow, MERGE)
        del with_of(validator)["validate-only"]
        self.assert_check_fails(self.check_validator, workflow, MERGE)

    def test_a_bare_boolean_validate_only_fails(self) -> None:
        """A validate-only written as YAML true, not the string, fails."""
        workflow = mutated(load_workflow(MAVEN))
        validator = validator_of(workflow, MAVEN)
        with_of(validator)["validate-only"] = True
        self.assert_check_fails(self.check_validator, workflow, MAVEN)

    def test_differing_pins_fail(self) -> None:
        """A validator at another commit than the scan fails."""
        workflow = mutated(load_workflow(GRADLE))
        validator = validator_of(workflow, GRADLE)
        validator["uses"] = f"{GRYPE_ACTION}@{'0' * 40}"
        self.assert_check_fails(self.check_validator, workflow, GRADLE)

    def test_differing_merge_pins_fail(self) -> None:
        """A merge validator at another commit than the scan fails."""
        workflow = mutated(load_workflow(MERGE))
        validator = validator_of(workflow, MERGE)
        validator["uses"] = f"{GRYPE_ACTION}@{'0' * 40}"
        self.assert_check_fails(self.check_validator, workflow, MERGE)

    def test_a_scan_input_the_validator_lacks_fails(self) -> None:
        """A policy input added to the scan alone fails."""
        workflow = mutated(load_workflow(MAVEN))
        scan = step_of(job_of(workflow, "grype"), GRYPE_STEP)
        with_of(scan)["declared-source"] = (
            "${{ inputs.grype_declared_source }}"
        )
        self.assert_check_fails(self.check_validator, workflow, MAVEN)

    def test_a_fixed_scan_input_the_validator_lacks_fails(self) -> None:
        """A fixed value added to the scan alone fails."""
        workflow = mutated(load_workflow(MERGE))
        scan = step_of(job_of(workflow, "grype"), GRYPE_STEP)
        with_of(scan)["gate-when"] = "always"
        self.assert_check_fails(self.check_validator, workflow, MERGE)

    def test_a_scan_dropping_a_policy_input_fails(self) -> None:
        """A scan no longer passing a policy input as the lane's fails."""
        workflow = mutated(load_workflow(GRADLE))
        scan = step_of(job_of(workflow, "grype"), GRYPE_STEP)
        validator = validator_of(workflow, GRADLE)
        with_of(scan)["fail-on"] = "medium"
        del with_of(validator)["fail-on"]
        self.assert_check_fails(self.check_validator, workflow, GRADLE)

    def test_a_merge_scan_dropping_permit_fail_fails(self) -> None:
        """A merge scan no longer passing permit-fail fails."""
        workflow = mutated(load_workflow(MERGE))
        scan = step_of(job_of(workflow, "grype"), GRYPE_STEP)
        validator = validator_of(workflow, MERGE)
        del with_of(scan)["permit-fail"]
        del with_of(validator)["permit-fail"]
        self.assert_check_fails(self.check_validator, workflow, MERGE)

    def test_an_sbom_passed_to_the_validator_fails(self) -> None:
        """A validator given something to scan fails."""
        workflow = mutated(load_workflow(MAVEN))
        validator = validator_of(workflow, MAVEN)
        with_of(validator)["sbom"] = f"{SBOM_DIR}/sbom-cyclonedx.json"
        self.assert_check_fails(self.check_validator, workflow, MAVEN)

    def test_a_target_passed_to_the_validator_fails(self) -> None:
        """A validator given a target to scan fails."""
        workflow = mutated(load_workflow(MERGE))
        validator = validator_of(workflow, MERGE)
        with_of(validator)["target"] = "dir:."
        self.assert_check_fails(self.check_validator, workflow, MERGE)

    def test_a_token_passed_to_the_validator_fails(self) -> None:
        """A validator given the scan's token, built from secrets, fails."""
        workflow = mutated(load_workflow(MERGE))
        validator = validator_of(workflow, MERGE)
        with_of(validator)["github-token"] = "${{ secrets.GITHUB_TOKEN }}"
        self.assert_check_fails(self.check_validator, workflow, MERGE)

    def test_a_checkout_in_the_job_fails(self) -> None:
        """A validation job that checks out fails."""
        for lane in (GRADLE, MERGE):
            with self.subTest(lane=lane):
                workflow = mutated(load_workflow(lane))
                steps_of(validate_job_of(workflow, lane)).insert(
                    0,
                    {
                        "name": "Checkout",
                        "uses": f"{CHECKOUT_ACTIONS[0]}@{'0' * 40}",
                    },
                )
                self.assert_check_fails(
                    self.check_job_fetches_one_action, workflow, lane
                )

    def test_a_harden_runner_in_the_job_fails(self) -> None:
        """A validation job under harden-runner fails."""
        for lane in (MAVEN, MERGE):
            with self.subTest(lane=lane):
                workflow = mutated(load_workflow(lane))
                steps_of(validate_job_of(workflow, lane)).insert(
                    0,
                    {
                        "name": "Harden runner",
                        "uses": f"step-security/harden-runner@{'0' * 40}",
                    },
                )
                self.assert_check_fails(
                    self.check_job_fetches_one_action, workflow, lane
                )

    def test_a_shell_policy_check_fails(self) -> None:
        """A run: step reading a policy input fails."""
        for lane in (GRADLE, MERGE):
            with self.subTest(lane=lane):
                workflow = mutated(load_workflow(lane))
                steps_of(validate_job_of(workflow, lane)).append(
                    {
                        "name": "Validate grype_fail_on",
                        "env": {"FAIL_ON": "${{ inputs.grype_fail_on }}"},
                        "run": "true",
                    }
                )
                self.assert_check_fails(
                    self.check_no_shell_validator, workflow, lane
                )

    def test_an_ecosystems_step_reading_more_fails(self) -> None:
        """An ecosystems check reading a policy input too fails."""
        workflow = mutated(load_workflow(MAVEN))
        step = step_of(job_of(workflow, VALIDATE_JOB), ECOSYSTEMS_VALIDATE)
        section(step, "env")["GATE_WHEN"] = "${{ inputs.grype_gate_when }}"
        self.assert_check_fails(self.check_ecosystems_step, workflow)
        self.assert_check_fails(self.check_no_shell_validator, workflow, MAVEN)

    def test_one_pinned_line_fails(self) -> None:
        """A lane with the pin on the scan alone fails."""
        for lane in (MAVEN, MERGE):
            with self.subTest(lane=lane):
                content = read_text(lane).replace(GRYPE_LINE, "", 1)
                self.assert_check_fails(self.check_pin_text, content, lane)

    def test_a_third_reference_fails(self) -> None:
        """A lane with a third grype-scan-action reference fails."""
        for lane in (GRADLE, MERGE):
            with self.subTest(lane=lane):
                content = (
                    read_text(lane) + f"\n# uses: {GRYPE_ACTION}@{'0' * 40}\n"
                )
                self.assert_check_fails(self.check_pin_text, content, lane)


class GateValidateCheck(ContractCase):
    """testing.yaml's validate-only rejection.

    The job runs the lanes' validation step itself, at the lanes' pin
    with each lane input's default as a literal and a gate-when the
    action does not know, and asserts the step failed: a bad policy
    value fails in seconds. Like the lanes' job it runs that one
    action, with no checkout and no harden-runner; that validate-only
    makes no network request is the action's own contract, tested in
    its repository, which this job asserts nothing about. Each lane's
    defaults are read from the lane, so a default that moves fails
    here until the case follows.
    """

    def defaults_of(self, lane: str) -> dict[str, str]:
        """Return each validated input's lane default, by action input."""
        workflow = load_workflow(lane)
        validator = validator_of(workflow, lane)
        inputs = call_inputs(workflow)
        defaults: dict[str, str] = {}
        for name, expression in policy_inputs(validator).items():
            lane_input = expression[len("${{ inputs.") : -len(" }}")]
            defaults[name] = text(section(inputs, lane_input).get("default"))
        return defaults

    def check_job_exists(self, testing: Workflow) -> None:
        """Fail unless the check job is there, with no permission."""
        self.assertIn(CHECK_JOB, jobs_of(testing), f"no {CHECK_JOB} job")
        self.assertEqual(
            job_of(testing, CHECK_JOB).get("permissions"),
            {},
            f"{CHECK_JOB} needs no permission",
        )

    def check_job_fetches_one_action(self, testing: Workflow) -> None:
        """Fail unless the validator is the job's only action step."""
        self.assertEqual(
            uses_in(job_of(testing, CHECK_JOB)),
            [GRYPE_USES],
            f"{CHECK_JOB} must run no action but the validator, as the"
            f" lanes' {VALIDATE_JOB} does: no checkout, no harden-runner",
        )

    def check_validator(self, testing: Workflow, lane: str) -> None:
        """Fail unless the step passes the lane's defaults, as literals."""
        step = step_of(job_of(testing, CHECK_JOB), GATE_VALIDATE)
        self.assertEqual(uses_of(step), GRYPE_USES, f"'{GATE_VALIDATE}' uses")
        self.assertIs(
            step.get("continue-on-error"),
            True,
            f"'{GATE_VALIDATE}' must continue on error, for the rejection",
        )
        passed = {name: text(value) for name, value in with_of(step).items()}
        gate_when = passed.pop("gate-when", None)
        self.assertIsNotNone(gate_when, f"{CHECK_JOB} must pass gate-when")
        assert gate_when is not None
        self.assertNotIn(
            gate_when,
            GATE_WHEN_VALUES,
            f"{CHECK_JOB} must pass a gate-when the action does not know",
        )
        self.assertNotIn(
            "${{",
            gate_when,
            f"{CHECK_JOB} must pass gate-when as a literal",
        )
        want = {"validate-only": "true", **self.defaults_of(lane)}
        del want["gate-when"]
        self.assertEqual(
            passed,
            want,
            f"{CHECK_JOB}'s '{GATE_VALIDATE}' must pass {lane}'s defaults",
        )

    def check_assertion(self, testing: Workflow) -> None:
        """Fail unless a step after the validator reads its outcome."""
        job = job_of(testing, CHECK_JOB)
        validator = step_of(job, GATE_VALIDATE)
        verdict = step_of(job, CHECK_ASSERT)
        steps = steps_of(job)
        self.assertLess(
            steps.index(validator),
            steps.index(verdict),
            f"'{CHECK_ASSERT}' must follow '{GATE_VALIDATE}'",
        )
        self.assertNotIn(
            "continue-on-error",
            verdict,
            f"'{CHECK_ASSERT}' must fail the job",
        )
        self.assertIn(
            f"${{{{ steps.{text(validator.get('id'))}.outcome }}}}",
            [text(value) for value in scalars(verdict.get("env"))],
            f"'{CHECK_ASSERT}' must read the validator's outcome",
        )

    def test_the_job_exists(self) -> None:
        """testing.yaml holds the check job."""
        self.check_job_exists(load_workflow(TESTING))

    def test_the_job_fetches_one_action(self) -> None:
        """The job runs no action but the validator."""
        self.check_job_fetches_one_action(load_workflow(TESTING))

    def test_the_step_passes_each_lanes_defaults(self) -> None:
        """The step passes each lane's defaults; so the lanes agree."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_validator(load_workflow(TESTING), lane)

    def test_the_verdict_is_asserted(self) -> None:
        """A step after the validator judges its outcome."""
        self.check_assertion(load_workflow(TESTING))

    def test_a_permission_fails(self) -> None:
        """A job granted a permission fails the check."""
        testing = mutated(load_workflow(TESTING))
        job_of(testing, CHECK_JOB)["permissions"] = {"contents": "read"}
        self.assert_check_fails(self.check_job_exists, testing)

    def test_a_harden_runner_in_the_job_fails(self) -> None:
        """A job under harden-runner fails the check."""
        testing = mutated(load_workflow(TESTING))
        steps_of(job_of(testing, CHECK_JOB)).insert(
            0,
            {
                "name": "Harden runner",
                "uses": f"step-security/harden-runner@{'0' * 40}",
            },
        )
        self.assert_check_fails(self.check_job_fetches_one_action, testing)

    def test_a_checkout_fails(self) -> None:
        """A job that checks out fails the check."""
        testing = mutated(load_workflow(TESTING))
        steps_of(job_of(testing, CHECK_JOB)).insert(
            0,
            {"name": "Checkout", "uses": f"{CHECKOUT_ACTIONS[0]}@{'0' * 40}"},
        )
        self.assert_check_fails(self.check_job_fetches_one_action, testing)

    def test_a_default_that_moved_fails(self) -> None:
        """A step passing another value than the lane's default fails."""
        testing = mutated(load_workflow(TESTING))
        step = step_of(job_of(testing, CHECK_JOB), GATE_VALIDATE)
        with_of(step)["dependency-policy"] = "all"
        self.assert_check_fails(self.check_validator, testing, MAVEN)

    def test_a_step_that_stops_the_job_fails(self) -> None:
        """A step without continue-on-error fails the check."""
        testing = mutated(load_workflow(TESTING))
        step = step_of(job_of(testing, CHECK_JOB), GATE_VALIDATE)
        del step["continue-on-error"]
        self.assert_check_fails(self.check_validator, testing, GRADLE)

    def test_a_valid_gate_when_fails(self) -> None:
        """A step passing a gate-when the action accepts fails the check."""
        testing = mutated(load_workflow(TESTING))
        step = step_of(job_of(testing, CHECK_JOB), GATE_VALIDATE)
        with_of(step)["gate-when"] = "dependencies-changed"
        self.assert_check_fails(self.check_validator, testing, MAVEN)

    def test_a_gate_when_expression_fails(self) -> None:
        """A step passing gate-when as an expression fails the check."""
        testing = mutated(load_workflow(TESTING))
        step = step_of(job_of(testing, CHECK_JOB), GATE_VALIDATE)
        with_of(step)["gate-when"] = "${{ matrix.gate_when }}"
        self.assert_check_fails(self.check_validator, testing, GRADLE)

    def test_an_unread_outcome_fails(self) -> None:
        """An assertion step that reads no outcome fails the check."""
        testing = mutated(load_workflow(TESTING))
        verdict = step_of(job_of(testing, CHECK_JOB), CHECK_ASSERT)
        section(verdict, "env")["OUTCOME"] = "failure"
        self.assert_check_fails(self.check_assertion, testing)

    def test_an_assertion_that_cannot_fail_fails(self) -> None:
        """An assertion step with continue-on-error fails the check."""
        testing = mutated(load_workflow(TESTING))
        verdict = step_of(job_of(testing, CHECK_JOB), CHECK_ASSERT)
        verdict["continue-on-error"] = True
        self.assert_check_fails(self.check_assertion, testing)


class MetadataDetection(ContractCase):
    """Detection in the repository-metadata job: pin, inputs and output."""

    def check_pin_in_text(self, path: str, count: int = 1) -> None:
        """Fail unless the file calls the action at the pin, comment and all.

        Every call is at the pin, so the repository holds one.
        """
        source = read_text(path)
        self.assertEqual(
            source.count(META_LINE),
            count,
            f"{path}: {META_LINE} must appear {count} time(s)",
        )
        self.assertEqual(
            source.count(f"{META_ACTION}@"),
            count,
            f"{path}: every repository-metadata-action call must be at"
            f" {META_PIN}",
        )

    def check_step(self, workflow: Workflow, preset: str) -> None:
        """Fail unless the metadata step detects with the lane's inputs."""
        step = step_of(job_of(workflow, META_JOB), META_STEP)
        self.assertEqual(text(step.get("id")), META_STEP_ID, "step id")
        self.assertEqual(uses_of(step), META_USES, f"'{META_STEP}' uses")
        passed = with_of(step)
        want = {
            # Only when a scan can consume it: without the SBOM no Grype
            # job runs, and under 'always' the scan ignores the verdict.
            "dependency_change": f"${{{{ {DETECT_IF} }}}}",
            "gerrit_refspec": "${{ inputs.gerrit_refspec }}",
            # Empty selects every preset; a narrowed selection keeps
            # the lane's own.
            "dependency_ecosystems": lane_ecosystems(preset),
            # Repository-wide: a Maven parent chain or a Gradle included
            # build crosses directory boundaries path_prefix cannot
            # follow.
            "dependency_path_prefix": ".",
        }
        got = {field: text(passed.get(field)) for field in want}
        self.assertEqual(got, want, f"'{META_STEP}' with:")
        self.assertEqual(
            text(passed.get("dependency_patterns")),
            CALLER_PATTERNS,
            f"'{META_STEP}' must watch the caller's patterns alone in the"
            f" {preset} lane",
        )
        self.assertEqual(
            text(passed.get("dependency_base")),
            "",
            f"'{META_STEP}' must leave the base to the detector",
        )

    def check_job_output(self, workflow: Workflow) -> None:
        """Fail unless the job publishes the step's dependencies_changed."""
        self.assertEqual(
            text(
                outputs_of(job_of(workflow, META_JOB)).get(
                    "dependencies_changed"
                )
            ),
            f"${{{{ steps.{META_STEP_ID}.outputs.dependencies_changed }}}}",
            f"{META_JOB}'s dependencies_changed must be the step's output",
        )

    def check_checkout_depth(self, workflow: Workflow) -> None:
        """Fail unless the job's actions/checkout holds the parent of HEAD.

        The parent of HEAD is the base on a pull request: 2 holds it, as
        does 0, the whole history; 1, or the default of 1, does not.
        """
        depths = [
            text(with_of(step).get("fetch-depth", "unset"))
            for step in steps_of(job_of(workflow, META_JOB))
            if is_action(step, "actions/checkout")
        ]
        self.assertNotEqual(
            depths, [], f"the {META_JOB} job has no actions/checkout step"
        )
        for depth in depths:
            self.assertTrue(
                depth.isdigit() and depth != "1",
                f"the {META_JOB} job's actions/checkout fetches depth"
                f" '{depth}'; detection needs 2 or more",
            )

    def check_order(self, workflow: Workflow) -> None:
        """Fail unless the metadata step follows every checkout."""
        job = job_of(workflow, META_JOB)
        checkout = last_checkout(job)
        step = step_index(job, META_STEP)
        self.assertTrue(
            checkout != -1 and checkout < step,
            f"'{META_STEP}' (step {step}) must follow the last checkout"
            f" ({checkout})",
        )

    def check_no_old_wiring(self, path: str) -> None:
        """Fail if the file still holds the dependency-change job's wiring."""
        source = read_text(path)
        left = [needle for needle in OLD_WIRING if needle in source]
        self.assertEqual(left, [], f"{path} still holds: {left}")
        self.assertNotIn(
            OLD_JOB,
            jobs_of(load_workflow(path)),
            f"{path} still has a {OLD_JOB} job",
        )

    def test_the_pin_appears_once_with_its_comment(self) -> None:
        """Each workflow calling the action holds the v0.5.1 pin, once."""
        for path in (*LANES, MERGE, TESTING):
            with self.subTest(path=path):
                self.check_pin_in_text(path)

    def test_the_step_detects_with_the_lanes_inputs(self) -> None:
        """Each lane's metadata step detects with the lane's inputs."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_step(load_workflow(lane), PRESETS[lane])

    def test_the_job_publishes_the_verdict(self) -> None:
        """Each lane's metadata job publishes dependencies_changed."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_job_output(load_workflow(lane))

    def test_the_checkout_holds_the_parent(self) -> None:
        """Each lane's metadata checkout fetches at least two commits."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_checkout_depth(load_workflow(lane))

    def test_detection_follows_the_checkout(self) -> None:
        """Each lane gathers metadata after its checkouts."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_order(load_workflow(lane))

    def test_the_old_wiring_is_gone(self) -> None:
        """No workflow calls the detector directly or reads its sidecar."""
        for path in (*LANES, MERGE, TESTING):
            with self.subTest(path=path):
                self.check_no_old_wiring(path)

    def test_a_copy_at_another_pin_fails(self) -> None:
        """A second call at another pin fails the check."""
        source = read_text(MAVEN) + f"\n# uses: {META_ACTION}@{'0' * 40}\n"
        with mock.patch(f"{__name__}.read_text", return_value=source):
            self.assert_check_fails(self.check_pin_in_text, MAVEN)

    def test_the_old_pin_fails(self) -> None:
        """The metadata step at v0.3.3 fails the check."""
        old = "2206d754f65f1a90f57b49be546712c5f594def2  # v0.3.3"
        source = read_text(GRADLE).replace(f"{META_PIN}  # v0.5.1", old)
        with mock.patch(f"{__name__}.read_text", return_value=source):
            self.assert_check_fails(self.check_pin_in_text, GRADLE)

    def test_detection_left_on_fails(self) -> None:
        """Detection on whatever the policy says fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        step = step_of(job_of(workflow, META_JOB), META_STEP)
        with_of(step)["dependency_change"] = "true"
        self.assert_check_fails(self.check_step, workflow, "maven")

    def test_a_missing_gerrit_refspec_fails(self) -> None:
        """A step not told about the Gerrit checkout fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        step = step_of(job_of(workflow, META_JOB), META_STEP)
        del with_of(step)["gerrit_refspec"]
        self.assert_check_fails(self.check_step, workflow, "gradle")

    def test_a_narrowed_prefix_fails(self) -> None:
        """A detector held to a path prefix fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        step = step_of(job_of(workflow, META_JOB), META_STEP)
        with_of(step)["dependency_path_prefix"] = "${{ inputs.path_prefix }}"
        self.assert_check_fails(self.check_step, workflow, "gradle")

    def test_a_hard_coded_ecosystem_fails(self) -> None:
        """A step narrowed to the lane's own preset fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        step = step_of(job_of(workflow, META_JOB), META_STEP)
        with_of(step)["dependency_ecosystems"] = "maven"
        self.assert_check_fails(self.check_step, workflow, "maven")

    def test_unprefixed_ecosystems_fail(self) -> None:
        """A narrowed selection that can drop the lane's preset fails."""
        workflow = mutated(load_workflow(GRADLE))
        step = step_of(job_of(workflow, META_JOB), META_STEP)
        with_of(step)["dependency_ecosystems"] = ECOSYSTEMS_INPUT
        self.assert_check_fails(self.check_step, workflow, "gradle")

    def test_the_other_lanes_prefix_fails(self) -> None:
        """A lane prefixing the other lane's preset fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        step = step_of(job_of(workflow, META_JOB), META_STEP)
        with_of(step)["dependency_ecosystems"] = lane_ecosystems("gradle")
        self.assert_check_fails(self.check_step, workflow, "maven")

    def test_a_fixed_pattern_fails(self) -> None:
        """A step adding a fixed pattern to the caller's fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        step = step_of(job_of(workflow, META_JOB), META_STEP)
        with_of(step)["dependency_patterns"] = (
            f".mvn/jvm.config\n{CALLER_PATTERNS}\n"
        )
        self.assert_check_fails(self.check_step, workflow, "maven")

    def test_dropped_caller_patterns_fail(self) -> None:
        """A step ignoring grype_dependency_patterns fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        step = step_of(job_of(workflow, META_JOB), META_STEP)
        with_of(step)["dependency_patterns"] = "*.gradle\n*.gradle.kts"
        self.assert_check_fails(self.check_step, workflow, "gradle")

    def test_a_missing_job_output_fails(self) -> None:
        """A metadata job without the output fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        job_of(workflow, META_JOB).pop("outputs", None)
        self.assert_check_fails(self.check_job_output, workflow)

    def test_a_shallow_checkout_fails(self) -> None:
        """A checkout at depth 1, or with no depth, fails the check."""
        for depth in ("1", None):
            with self.subTest(depth=depth):
                workflow = mutated(load_workflow(MAVEN))
                for step in steps_of(job_of(workflow, META_JOB)):
                    if is_action(step, "actions/checkout"):
                        if depth is None:
                            with_of(step).pop("fetch-depth", None)
                        else:
                            with_of(step)["fetch-depth"] = int(depth)
                self.assert_check_fails(self.check_checkout_depth, workflow)

    def test_detection_before_the_checkout_fails(self) -> None:
        """The metadata step moved ahead of the checkout fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        job = job_of(workflow, META_JOB)
        steps = steps_of(job)
        steps.insert(0, steps.pop(step_index(job, META_STEP)))
        self.assert_check_fails(self.check_order, workflow)

    def test_the_old_detector_fails(self) -> None:
        """A direct dependency-change-action call fails the check."""
        source = read_text(MAVEN) + f"\n# uses: {OLD_DETECTOR}{'0' * 40}\n"
        with mock.patch(f"{__name__}.read_text", return_value=source):
            self.assert_check_fails(self.check_no_old_wiring, MAVEN)

    def test_an_old_job_fails(self) -> None:
        """A dependency-change job left in a lane fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        jobs_of(workflow)[OLD_JOB] = {"runs-on": "ubuntu-latest"}
        with mock.patch(f"{__name__}.load_workflow", return_value=workflow):
            self.assert_check_fails(self.check_no_old_wiring, GRADLE)


class GrypeConsumer(ContractCase):
    """The Grype job reads the guarded verdict, and scans regardless."""

    def check_needs(self, workflow: Workflow) -> None:
        """Fail unless the Grype job needs build and repository-metadata."""
        grype = job_of(workflow, "grype")
        self.assertEqual(
            sorted(needs_of(grype)),
            ["build", META_JOB],
            "the grype job must need build and repository-metadata",
        )

    def check_condition(self, workflow: Workflow) -> None:
        """Fail unless a failed or skipped metadata job still scans.

        GitHub skips a job whose needs failed or skipped unless its
        condition says otherwise; !cancelled() does, and the condition
        names no metadata result.
        """
        self.assertEqual(
            text(job_of(workflow, "grype").get("if")),
            GRYPE_IF,
            "the grype job's condition",
        )

    def check_verdict(self, workflow: Workflow) -> None:
        """Fail unless the scanner and job output read the guarded verdict."""
        grype = job_of(workflow, "grype")
        passed = with_of(step_of(grype, GRYPE_STEP))
        self.assertEqual(
            text(passed.get("dependencies-changed")),
            f"${{{{ {VERDICT} }}}}",
            f"'{GRYPE_STEP}' must read the guarded verdict",
        )
        self.assertNotIn(
            "dependency-change-manifest",
            passed,
            f"'{GRYPE_STEP}' must not read a sidecar",
        )
        self.assertEqual(
            text(outputs_of(grype).get("dependencies_changed")),
            f"${{{{ {VERDICT} }}}}",
            "the grype job's dependencies_changed must be the verdict"
            " the scanner reads",
        )
        self.assertEqual(
            text(
                section(
                    call_outputs(workflow), "grype_dependencies_changed"
                ).get("value")
            ),
            "${{ jobs.grype.outputs.dependencies_changed }}",
            "output grype_dependencies_changed must be the grype job's",
        )

    def check_sbom_output(self, workflow: Workflow) -> None:
        """Fail unless the build job publishes its SBOM upload's ID."""
        build = job_of(workflow, "build")
        upload_id = text(step_of(build, SBOM_UPLOAD_STEP).get("id")) or "?"
        self.assertEqual(
            text(outputs_of(build).get("sbom_artifact_id")),
            f"${{{{ steps.{upload_id}.outputs.artifact-id }}}}",
            "build's sbom_artifact_id must be the artifact-id output of"
            f" '{SBOM_UPLOAD_STEP}'",
        )

    def check_download(self, workflow: Workflow) -> None:
        """Fail unless the SBOM download goes by ID into place, pre-scan."""
        grype = job_of(workflow, "grype")
        step = step_of(grype, SBOM_DOWNLOAD_STEP)
        passed = with_of(step)
        got = {
            "if": text(step.get("if")),
            "artifact-ids": text(passed.get("artifact-ids")),
            "merge-multiple": text(passed.get("merge-multiple")),
            "name": text(passed.get("name")),
            "path": text(passed.get("path")),
        }
        want = {
            # The grype job runs only when the SBOM uploaded, so the
            # download needs no condition of its own.
            "if": "",
            # By the exact upload, never by a name another job could
            # reuse, and with merge-multiple, which drops the
            # artefact-name level a download by ID adds.
            "artifact-ids": "${{ needs.build.outputs.sbom_artifact_id }}",
            "merge-multiple": "true",
            "name": "",
            "path": SBOM_DIR,
        }
        self.assertEqual(got, want, f"'{SBOM_DOWNLOAD_STEP}'")
        index = step_index(grype, SBOM_DOWNLOAD_STEP)
        scan = step_index(grype, GRYPE_STEP)
        self.assertTrue(
            index != -1 and scan != -1 and index < scan,
            f"'{SBOM_DOWNLOAD_STEP}' must precede '{GRYPE_STEP}'",
        )

    def check_downloads(self, workflow: Workflow) -> None:
        """Fail unless the SBOM is the Grype job's only download."""
        downloads = [
            text(step.get("name"))
            for step in steps_of(job_of(workflow, "grype"))
            if is_action(step, "actions/download-artifact")
        ]
        self.assertEqual(
            downloads,
            [SBOM_DOWNLOAD_STEP],
            f"the grype job downloads: {downloads}",
        )

    def test_the_grype_needs(self) -> None:
        """Each lane's Grype job needs build and repository-metadata."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_needs(load_workflow(lane))

    def test_the_grype_condition(self) -> None:
        """Each lane's Grype job tolerates a failed metadata job."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_condition(load_workflow(lane))

    def test_the_guarded_verdict(self) -> None:
        """Each lane's scanner reads the verdict through the guard."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_verdict(load_workflow(lane))

    def test_the_build_publishes_its_sbom_upload(self) -> None:
        """Each lane's build job publishes the SBOM upload's ID."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_sbom_output(load_workflow(lane))

    def test_the_sbom_download(self) -> None:
        """Each lane downloads the SBOM by ID, before the scan."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_download(load_workflow(lane))

    def test_the_sbom_is_the_only_download(self) -> None:
        """No lane's Grype job downloads anything but the SBOM."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_downloads(load_workflow(lane))

    def test_grype_without_repository_metadata_fails(self) -> None:
        """A Grype job not needing repository-metadata fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        job_of(workflow, "grype")["needs"] = ["build"]
        self.assert_check_fails(self.check_needs, workflow)

    def test_grype_without_build_fails(self) -> None:
        """A Grype job not needing build fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        job_of(workflow, "grype")["needs"] = [META_JOB]
        self.assert_check_fails(self.check_needs, workflow)

    def test_a_condition_without_cancelled_fails(self) -> None:
        """A Grype job that a failed metadata job would skip fails."""
        workflow = mutated(load_workflow(MAVEN))
        job_of(workflow, "grype")["if"] = (
            "${{ needs.build.outputs.sbom_uploaded == 'true'"
            " && inputs.grype_enabled }}"
        )
        self.assert_check_fails(self.check_condition, workflow)

    def test_a_condition_on_metadata_success_fails(self) -> None:
        """A Grype job that waits on metadata success fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        job = job_of(workflow, "grype")
        job["if"] = text(job["if"]).replace(
            "}}", "&& needs.repository-metadata.result == 'success' }}"
        )
        self.assert_check_fails(self.check_condition, workflow)

    def test_an_unguarded_verdict_fails(self) -> None:
        """A scanner reading the output whatever the job's result fails."""
        workflow = mutated(load_workflow(MAVEN))
        step = step_of(job_of(workflow, "grype"), GRYPE_STEP)
        with_of(step)["dependencies-changed"] = (
            "${{ needs.repository-metadata.outputs.dependencies_changed }}"
        )
        self.assert_check_fails(self.check_verdict, workflow)

    def test_a_sidecar_manifest_fails(self) -> None:
        """A scanner still reading a sidecar fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        step = step_of(job_of(workflow, "grype"), GRYPE_STEP)
        with_of(step)["dependency-change-manifest"] = (
            "dependency-change/dependency-change.json"
        )
        self.assert_check_fails(self.check_verdict, workflow)

    def test_a_crossed_verdict_output_fails(self) -> None:
        """A job output reading the raw metadata output fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        outputs_of(job_of(workflow, "grype"))["dependencies_changed"] = (
            "${{ needs.repository-metadata.outputs.dependencies_changed }}"
        )
        self.assert_check_fails(self.check_verdict, workflow)

    def test_a_download_by_name_fails(self) -> None:
        """The SBOM download by artefact name fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        step = step_of(job_of(workflow, "grype"), SBOM_DOWNLOAD_STEP)
        passed = with_of(step)
        del passed["artifact-ids"]
        passed["name"] = f"sbom-files-maven{SUFFIX}"
        self.assert_check_fails(self.check_download, workflow)

    def test_a_download_after_the_scan_fails(self) -> None:
        """The SBOM download moved behind the scan fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        grype = job_of(workflow, "grype")
        steps = steps_of(grype)
        steps.append(steps.pop(step_index(grype, SBOM_DOWNLOAD_STEP)))
        self.assert_check_fails(self.check_download, workflow)

    def test_an_extra_download_fails(self) -> None:
        """A second download in the Grype job fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        grype = job_of(workflow, "grype")
        extra = copy.deepcopy(step_of(grype, SBOM_DOWNLOAD_STEP))
        extra["name"] = "Download dependency-change sidecar"
        steps_of(grype).insert(0, extra)
        self.assert_check_fails(self.check_downloads, workflow)

    def test_a_flag_as_the_sbom_output_fails(self) -> None:
        """A build output naming the step, not its artifact-id, fails."""
        workflow = mutated(load_workflow(MAVEN))
        outputs_of(job_of(workflow, "build"))["sbom_artifact_id"] = (
            "${{ steps.upload-sbom.outcome }}"
        )
        self.assert_check_fails(self.check_sbom_output, workflow)


class TuningInputs(ContractCase):
    """The detection, bypass and merge-lane policy inputs."""

    def check_verify_inputs(self, workflow: Workflow) -> None:
        """Fail unless each new verify input is declared and passed on."""
        inputs = call_inputs(workflow)
        for name in NEW_VERIFY_INPUTS:
            declared = section(inputs, name)
            self.assertEqual(
                (
                    text(declared.get("type")),
                    text(declared.get("default")),
                    declared.get("required"),
                ),
                ("string", "", False),
                f"input {name} must be an optional string defaulting to ''",
            )
        for name, job_id, step_name, target in VERIFY_INPUTS:
            passed = with_of(step_of(job_of(workflow, job_id), step_name))
            self.assertEqual(
                text(passed.get(target)),
                f"${{{{ inputs.{name} }}}}",
                f"'{step_name}' must pass inputs.{name} as {target}",
            )
        self.assertEqual(
            text(section(inputs, "grype_fail_on").get("default")),
            "medium",
            "grype_fail_on keeps its default",
        )

    def check_merge_inputs(self, workflow: Workflow) -> None:
        """Fail unless the merge lane's inputs reach a report-only scan."""
        inputs = call_inputs(workflow)
        grype = job_of(workflow, "grype")
        passed = with_of(step_of(grype, GRYPE_STEP))
        for name, kind, default, target in MERGE_INPUTS:
            declared = section(inputs, name)
            self.assertEqual(
                (text(declared.get("type")), text(declared.get("default"))),
                (kind, default),
                f"input {name} must be a {kind} defaulting to '{default}'",
            )
            self.assertEqual(
                text(passed.get(target)),
                f"${{{{ inputs.{name} }}}}",
                f"'{GRYPE_STEP}' must pass inputs.{name} as {target}",
            )
        # The merge lane reports, never gates.
        self.assertEqual(text(passed.get("permit-fail")), "true")
        self.assertIs(grype.get("continue-on-error"), True)
        self.assertEqual(uses_of(step_of(grype, GRYPE_STEP)), GRYPE_USES)

    def test_the_verify_inputs(self) -> None:
        """Each verify lane declares and passes its new inputs."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_verify_inputs(load_workflow(lane))

    def test_the_merge_inputs(self) -> None:
        """The merge lane declares and passes its policy inputs."""
        self.check_merge_inputs(load_workflow(MERGE))

    def test_a_dropped_bypass_fails(self) -> None:
        """A scanner not told the bypass repository fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        del with_of(step_of(job_of(workflow, "grype"), GRYPE_STEP))[
            "bypass-repository"
        ]
        self.assert_check_fails(self.check_verify_inputs, workflow)

    def test_a_defaulted_ecosystem_fails(self) -> None:
        """An ecosystems input with a non-empty default fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        call_inputs(workflow)["grype_dependency_ecosystems"]["default"] = (
            "maven"
        )
        self.assert_check_fails(self.check_verify_inputs, workflow)

    def test_a_missing_patterns_input_fails(self) -> None:
        """A lane without grype_dependency_patterns fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        del call_inputs(workflow)["grype_dependency_patterns"]
        self.assert_check_fails(self.check_verify_inputs, workflow)

    def test_a_literal_merge_fail_on_fails(self) -> None:
        """The merge scanner back on a literal fail-on fails the check."""
        workflow = mutated(load_workflow(MERGE))
        step = step_of(job_of(workflow, "grype"), GRYPE_STEP)
        with_of(step)["fail-on"] = "medium"
        self.assert_check_fails(self.check_merge_inputs, workflow)

    def test_a_changed_merge_default_fails(self) -> None:
        """A merge policy default other than the action's fails."""
        workflow = mutated(load_workflow(MERGE))
        call_inputs(workflow)["grype_dependency_policy"]["default"] = (
            "declared"
        )
        self.assert_check_fails(self.check_merge_inputs, workflow)

    def test_a_gating_merge_scan_fails(self) -> None:
        """A merge scan that may fail the run fails the check."""
        workflow = mutated(load_workflow(MERGE))
        step = step_of(job_of(workflow, "grype"), GRYPE_STEP)
        with_of(step)["permit-fail"] = "false"
        self.assert_check_fails(self.check_merge_inputs, workflow)


class GateVerdictOutputs(ContractCase):
    """The lanes publish the gate's verdict from the action's outputs."""

    OUTPUTS = (
        ("grype_gate_active", "gate_active", "gate-active"),
        ("grype_gate_reason", "gate_reason", "gate-reason"),
    )

    def check_outputs(self, workflow: Workflow) -> None:
        """Fail unless each verdict output flows from the scanner."""
        outputs = call_outputs(workflow)
        grype = outputs_of(job_of(workflow, "grype"))
        for output, job_output, action_output in self.OUTPUTS:
            self.assertEqual(
                text(section(outputs, output).get("value")),
                f"${{{{ jobs.grype.outputs.{job_output} }}}}",
                f"output {output} must be the grype job's {job_output}",
            )
            self.assertEqual(
                text(grype.get(job_output)),
                f"${{{{ steps.grype-audit.outputs.{action_output} }}}}",
                f"the grype job's {job_output} must be the action's"
                f" {action_output}",
            )

    def test_the_verdict_is_published(self) -> None:
        """Each lane publishes gate_active and gate_reason."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_outputs(load_workflow(lane))

    def test_a_missing_output_fails(self) -> None:
        """A lane without grype_gate_reason fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        del call_outputs(workflow)["grype_gate_reason"]
        self.assert_check_fails(self.check_outputs, workflow)

    def test_a_crossed_output_fails(self) -> None:
        """A job output reading the wrong action output fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        outputs_of(job_of(workflow, "grype"))["gate_active"] = (
            "${{ steps.grype-audit.outputs.gate-reason }}"
        )
        self.assert_check_fails(self.check_outputs, workflow)


def is_policy_lane(job: Job) -> bool:
    """Return whether ``job`` calls a verify lane under the policy."""
    passed = with_of(job)
    return (
        re.search(r"/(maven|gradle)-build-test\.yaml$", uses_of(job))
        is not None
        and passed.get("grype_gate_when") == "dependencies-changed"
        and passed.get("grype_enabled") is not False
        and passed.get("sbom_enabled") is not False
    )


def pinned_lanes(testing: Workflow) -> list[str]:
    """Return the policy lanes building a fixture at a pinned commit."""
    return [
        job_id
        for job_id, job in jobs_of(testing).items()
        if is_policy_lane(job)
        and COMMIT.match(text(with_of(job).get("ref"))) is not None
    ]


def resolved_lane(testing: Workflow, preset: str) -> list[str]:
    """Return the policy lanes building this repository's fixture."""
    return [
        job_id
        for job_id, job in jobs_of(testing).items()
        if is_policy_lane(job)
        and uses_of(job).endswith(f"/{preset}-build-test.yaml")
        and text(with_of(job).get("repository")) == ""
        and text(with_of(job).get("ref")) == ""
        and text(with_of(job).get("path_prefix")) == f"tests/fixtures/{preset}"
    ]


def readers_of(
    testing: Workflow, lane: str, output: str = "grype_gate_active"
) -> list[str]:
    """Return the jobs needing ``lane`` that read its ``output``."""
    wanted = f"needs.{lane}.outputs.{output}"
    return [
        job_id
        for job_id, job in jobs_of(testing).items()
        if lane in needs_of(job)
        and any(wanted in text(value) for value in scalars(job))
    ]


class PolicyLanes(ContractCase):
    """testing.yaml runs the unresolved and the resolved paths.

    The unresolved path: a lane running under the policy against a
    fixture at a pinned commit, whose HEAD is not the run's own commit,
    so the detector reports unresolved and the gate stays armed. The
    resolved path: each verify workflow building a fixture of this
    repository, at the run's own commit, so the detector resolves and
    the check job holds the gate to the verdict. Each lane's check job
    reads both verdicts the lane publishes: the dependency-change one
    its Grype job received and the gate's.
    """

    FIXTURE_MANIFESTS: ClassVar[dict[str, str]] = {
        "maven": "tests/fixtures/maven/pom.xml",
        "gradle": "tests/fixtures/gradle/settings.gradle.kts",
    }

    def check_pinned_lane(self, testing: Workflow) -> None:
        """Fail unless a lane runs the unresolved path."""
        self.assertNotEqual(
            pinned_lanes(testing),
            [],
            "no lane calls a verify workflow with grype_gate_when:"
            " dependencies-changed, Grype and the SBOM on, and ref pinned"
            " to a commit",
        )

    def check_resolved_lanes(self, testing: Workflow) -> None:
        """Fail unless each verify workflow runs the resolved path."""
        for preset in PRESETS.values():
            self.assertNotEqual(
                resolved_lane(testing, preset),
                [],
                f"no lane calls {preset}-build-test.yaml under the policy"
                f" on this repository's tests/fixtures/{preset}",
            )

    def check_readers(self, testing: Workflow) -> None:
        """Fail unless a job needing each policy lane reads its verdict."""
        lanes = pinned_lanes(testing)
        for preset in PRESETS.values():
            lanes.extend(resolved_lane(testing, preset))
        self.assertNotEqual(lanes, [], "no policy lanes to read")
        for lane in lanes:
            for output in ("grype_gate_active", "grype_dependencies_changed"):
                self.assertNotEqual(
                    readers_of(testing, lane, output),
                    [],
                    f"no job needing {lane} reads its {output}",
                )

    def test_a_lane_runs_the_unresolved_path(self) -> None:
        """A lane runs against a pinned fixture."""
        self.check_pinned_lane(load_workflow(TESTING))

    def test_lanes_run_the_resolved_path(self) -> None:
        """Each verify workflow runs against this repository's fixture."""
        self.check_resolved_lanes(load_workflow(TESTING))

    def test_the_fixtures_exist(self) -> None:
        """The file each resolved lane's preset watches is at its root."""
        for preset, manifest in self.FIXTURE_MANIFESTS.items():
            with self.subTest(preset=preset):
                self.assertTrue(
                    (ROOT / manifest).is_file(),
                    f"no {manifest}: the resolved {preset} lane has no"
                    " fixture",
                )

    def test_each_lane_has_a_reader(self) -> None:
        """A check job reads each policy lane's verdict."""
        self.check_readers(load_workflow(TESTING))

    def test_an_unpinned_lane_fails(self) -> None:
        """A pinned lane moved to a branch ref fails the check."""
        testing = mutated(load_workflow(TESTING))
        for lane in pinned_lanes(testing):
            with_of(job_of(testing, lane))["ref"] = "main"
        self.assert_check_fails(self.check_pinned_lane, testing)

    def test_a_lane_off_the_policy_fails(self) -> None:
        """A resolved lane under grype_gate_when: always fails the check."""
        testing = mutated(load_workflow(TESTING))
        for lane in resolved_lane(testing, "gradle"):
            with_of(job_of(testing, lane))["grype_gate_when"] = "always"
        self.assert_check_fails(self.check_resolved_lanes, testing)

    def test_a_reader_ignoring_the_verdict_fails(self) -> None:
        """A check job no longer reading grype_dependencies_changed fails."""
        testing = mutated(load_workflow(TESTING))
        lane = pinned_lanes(testing)[0]
        for job_id in readers_of(testing, lane, "grype_dependencies_changed"):
            for step in steps_of(job_of(testing, job_id)):
                step.pop("env", None)
        self.assert_check_fails(self.check_readers, testing)

    def test_a_lane_without_its_reader_fails(self) -> None:
        """A policy lane whose check job stops reading it fails."""
        testing = mutated(load_workflow(TESTING))
        lane = resolved_lane(testing, "maven")[0]
        for job_id in readers_of(testing, lane):
            job = job_of(testing, job_id)
            job["steps"] = [{"name": "Nothing", "run": "true"}]
            job.pop("env", None)
            job.pop("strategy", None)
        self.assert_check_fails(self.check_readers, testing)


class RepositoryTree(unittest.TestCase):
    """No symbolic link or submodule sits in the tree.

    The resolved lanes' check requires a resolved verdict, on the
    strength of the detector's rules for a pull request of this
    repository: HEAD is the run's commit, the whole history holds the
    base, and nothing in the tree is a symbolic link or a submodule,
    which repository-wide detection would otherwise report unresolved.
    """

    def test_no_link_or_submodule(self) -> None:
        """The index shows no 120000 or 160000 entry."""
        listing = subprocess.run(
            ["git", "ls-files", "-s"],
            check=True,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout
        entries = [
            line.split("\t", 1)[1]
            for line in listing.splitlines()
            if line.split(" ", 1)[0] in {"120000", "160000"}
        ]
        self.assertEqual(
            entries,
            [],
            "the tree holds a symbolic link or submodule, which leaves the"
            f" resolved lanes' detection unresolved: {entries}",
        )


def include_of(job: Job) -> list[object]:
    """Return the job's matrix ``include`` list itself, to add rows to."""
    include = section(section(job, "strategy"), "matrix").get("include")
    if not isinstance(include, list):
        raise AssertionError("the matrix has no include list")
    return cast("list[object]", include)


def include_rows(job: Job) -> list[dict[str, Any]]:
    """Return the ``include`` rows of the job's matrix, as a new list."""
    include = section(section(job, "strategy"), "matrix").get("include")
    if not isinstance(include, list):
        return []
    return [
        cast("dict[str, Any]", row)
        for row in cast("list[object]", include)
        if isinstance(row, dict)
    ]


def row_where(
    rows: list[dict[str, Any]], field: str, value: str
) -> dict[str, Any]:
    """Return the one row whose ``field`` is ``value``, or an empty one.

    GitHub Actions applies every matching include row in order, so a
    later row overrides the verdict an earlier one fixed; the shell
    check's ``yq`` printed one line per match and the comparison failed
    on more than one. Two or more matches fail here the same way.
    """
    matches = [row for row in rows if text(row.get(field)) == value]
    if len(matches) > 1:
        raise AssertionError(
            f"{len(matches)} include rows have {field} {value!r}, so a"
            f" later one overrides the first: {matches}"
        )
    empty: dict[str, Any] = {}
    return matches[0] if matches else empty


def matrix_axis(job: Job, field: str) -> list[str]:
    """Return the values of matrix axis ``field``."""
    axis = section(section(job, "strategy"), "matrix").get(field)
    if not isinstance(axis, list):
        return []
    return [text(value) for value in cast("list[object]", axis)]


class GateVerdictCases(ContractCase):
    """testing.yaml's fixed-expectation cases.

    The job needs both resolved lanes (for their SBOMs), runs
    repository-metadata-action at the lanes' pin with the lanes'
    detection inputs over a scratch repository with an explicit base,
    and the scanner at the lanes' pin with the lanes' policy, reading
    the verdict from the metadata step; its matrix fixes each case's
    expected verdict.
    """

    def check_job_exists(self, testing: Workflow) -> None:
        """Fail unless the cases job is there."""
        self.assertIn(CASES_JOB, jobs_of(testing), f"no {CASES_JOB} job")

    def check_needs(self, testing: Workflow) -> None:
        """Fail unless the job needs both resolved lanes."""
        job = job_of(testing, CASES_JOB)
        for preset in PRESETS.values():
            for lane in resolved_lane(testing, preset):
                self.assertTrue(
                    needs_mention(job, lane), f"{CASES_JOB} must need {lane}"
                )

    def check_detector(self, testing: Workflow) -> None:
        """Fail unless the detector runs at the pin over the scratch repo."""
        step = step_of(job_of(testing, CASES_JOB), DETECT_STEP)
        passed = with_of(step)
        want = {
            "uses": META_USES,
            "id": META_STEP_ID,
            "dependency_change": "true",
            # Every preset, or the matrix's narrowed selection prefixed
            # with the lane's preset, as the lanes pass it; no extra
            # patterns.
            "dependency_ecosystems": CASES_ECOSYSTEMS,
            "dependency_patterns": "",
            "dependency_base": "${{ steps.scratch.outputs.base }}",
            "dependency_path_prefix": ".",
        }
        got = {"uses": uses_of(step), "id": text(step.get("id"))}
        got.update(
            (field, text(passed.get(field)))
            for field in want
            if field not in got
        )
        self.assertEqual(got, want, f"{CASES_JOB}'s '{DETECT_STEP}'")

    def check_matrix(self, testing: Workflow) -> None:
        """Fail unless the matrix carries the lanes' inputs and verdicts."""
        job = job_of(testing, CASES_JOB)
        rows = include_rows(job)
        for preset, auxiliary in AUXILIARY_FILES.items():
            row = row_where(rows, "lane", preset)
            self.assertEqual(
                (
                    text(row.get("ecosystems")),
                    text(row.get("patterns")),
                    text(row.get("auxiliary_file")),
                ),
                ("", "", auxiliary),
                f"{CASES_JOB}'s {preset} row: the matrix's selection, no"
                f" extra patterns, and {auxiliary} for the auxiliary case",
            )
        for case, expected in CASE_VERDICTS.items():
            row = row_where(rows, "case", case)
            self.assertEqual(
                text(row.get("expected")),
                expected,
                f"{CASES_JOB}'s {case} case must expect {expected}",
            )
        self.assertEqual(
            matrix_axis(job, "lane"), ["maven", "gradle"], "matrix.lane"
        )
        self.assertEqual(
            matrix_axis(job, "case"), list(CASE_VERDICTS), "matrix.case"
        )
        self.assertEqual(
            matrix_axis(job, "ecosystems"),
            CASES_ECOSYSTEM_AXIS,
            "matrix.ecosystems",
        )

    def check_scanner(self, testing: Workflow) -> None:
        """Fail unless the scanner runs with the lanes' policy as literals."""
        step = step_of(job_of(testing, CASES_JOB), GRYPE_STEP)
        passed = with_of(step)
        want = {
            "gate-when": "dependencies-changed",
            "dependencies-changed": (
                f"${{{{ steps.{META_STEP_ID}.outputs.dependencies_changed }}}}"
            ),
            "dependency-change-manifest": "",
            "dependency-policy": "declared",
            "transitive-fail-on": "critical",
            "only-fixed": "true",
            "fail-on": "medium",
        }
        got = {field: text(passed.get(field)) for field in want}
        self.assertEqual(uses_of(step), GRYPE_USES, f"'{GRYPE_STEP}' uses")
        self.assertEqual(got, want, f"{CASES_JOB}'s '{GRYPE_STEP}'")

    def check_fail_on_default(self, workflow: Workflow) -> None:
        """Fail unless the lane's grype_fail_on default matches the cases."""
        self.assertEqual(
            text(
                section(call_inputs(workflow), "grype_fail_on").get("default")
            ),
            "medium",
            f"grype_fail_on must default to medium, as {CASES_JOB} scans",
        )

    def check_order(self, testing: Workflow) -> None:
        """Fail unless the job detects before it scans."""
        job = job_of(testing, CASES_JOB)
        self.assertLess(
            step_index(job, DETECT_STEP),
            step_index(job, GRYPE_STEP),
            f"{CASES_JOB} must detect before it scans",
        )

    def test_the_job_exists(self) -> None:
        """The cases job is there."""
        self.check_job_exists(load_workflow(TESTING))

    def test_the_job_needs_both_resolved_lanes(self) -> None:
        """The job needs each resolved lane."""
        self.check_needs(load_workflow(TESTING))

    def test_the_detector_pin_appears_in_the_text(self) -> None:
        """testing.yaml holds the pinned uses: line with its comment."""
        self.assertIn(
            META_LINE,
            read_text(TESTING),
            f"{TESTING}: no step runs {META_LINE}",
        )

    def test_the_detector(self) -> None:
        """The detector runs at the pin with the matrix inputs."""
        self.check_detector(load_workflow(TESTING))

    def test_the_matrix(self) -> None:
        """The matrix carries the lanes' inputs and each case's verdict."""
        self.check_matrix(load_workflow(TESTING))

    def test_the_scanner(self) -> None:
        """The scanner runs at the pin with the lanes' policy."""
        self.check_scanner(load_workflow(TESTING))

    def test_the_lanes_fail_on_default_matches(self) -> None:
        """Each lane's grype_fail_on defaults to what the cases scan at."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_fail_on_default(load_workflow(lane))

    def test_detection_precedes_the_scan(self) -> None:
        """The job detects before it scans."""
        self.check_order(load_workflow(TESTING))

    def test_a_missing_job_fails(self) -> None:
        """testing.yaml without the cases job fails the check."""
        testing = mutated(load_workflow(TESTING))
        del jobs_of(testing)[CASES_JOB]
        self.assert_check_fails(self.check_job_exists, testing)

    def test_a_dropped_need_fails(self) -> None:
        """The job needing one resolved lane only fails the check."""
        testing = mutated(load_workflow(TESTING))
        job_of(testing, CASES_JOB)["needs"] = resolved_lane(testing, "maven")
        self.assert_check_fails(self.check_needs, testing)

    def test_a_detector_without_a_base_fails(self) -> None:
        """A detector left to find its own base fails the check."""
        testing = mutated(load_workflow(TESTING))
        step = step_of(job_of(testing, CASES_JOB), DETECT_STEP)
        del with_of(step)["dependency_base"]
        self.assert_check_fails(self.check_detector, testing)

    def test_a_narrowed_detector_fails(self) -> None:
        """A detector held to the lane's own preset fails the check."""
        testing = mutated(load_workflow(TESTING))
        step = step_of(job_of(testing, CASES_JOB), DETECT_STEP)
        with_of(step)["dependency_ecosystems"] = "${{ matrix.lane }}"
        self.assert_check_fails(self.check_detector, testing)

    def test_a_scanner_reading_a_sidecar_fails(self) -> None:
        """A scanner reading a sidecar, not the step output, fails."""
        testing = mutated(load_workflow(TESTING))
        passed = with_of(step_of(job_of(testing, CASES_JOB), GRYPE_STEP))
        del passed["dependencies-changed"]
        passed["dependency-change-manifest"] = "dependency-change.json"
        self.assert_check_fails(self.check_scanner, testing)

    def test_a_swapped_verdict_fails(self) -> None:
        """A matrix expecting the gate off on a change fails the check."""
        testing = mutated(load_workflow(TESTING))
        for row in include_rows(job_of(testing, CASES_JOB)):
            if row.get("case") == "changed":
                row["expected"] = "false"
        self.assert_check_fails(self.check_matrix, testing)

    def test_a_conflicting_later_verdict_fails(self) -> None:
        """A second changed row, overriding the verdict, fails the check.

        GitHub Actions applies include rows in order, so the later row's
        'false' would win over the first row's 'true'.
        """
        testing = mutated(load_workflow(TESTING))
        include_of(job_of(testing, CASES_JOB)).append(
            {"case": "changed", "expected": "false"}
        )
        self.assert_check_fails(self.check_matrix, testing)

    def test_a_conflicting_later_lane_row_fails(self) -> None:
        """A second maven row, overriding its file, fails the check."""
        testing = mutated(load_workflow(TESTING))
        include_of(job_of(testing, CASES_JOB)).append(
            {"lane": "maven", "auxiliary_file": "pom.xml"}
        )
        self.assert_check_fails(self.check_matrix, testing)

    def test_a_detector_ignoring_the_selection_fails(self) -> None:
        """A detector on every preset whatever the matrix says fails."""
        testing = mutated(load_workflow(TESTING))
        step = step_of(job_of(testing, CASES_JOB), DETECT_STEP)
        with_of(step)["dependency_ecosystems"] = ""
        self.assert_check_fails(self.check_detector, testing)

    def test_an_unprefixed_detector_fails(self) -> None:
        """A detector on the bare narrowed selection fails the check."""
        testing = mutated(load_workflow(TESTING))
        step = step_of(job_of(testing, CASES_JOB), DETECT_STEP)
        with_of(step)["dependency_ecosystems"] = "${{ matrix.ecosystems }}"
        self.assert_check_fails(self.check_detector, testing)

    def test_a_dropped_narrowed_selection_fails(self) -> None:
        """A matrix running every preset alone fails the check."""
        testing = mutated(load_workflow(TESTING))
        section(section(job_of(testing, CASES_JOB), "strategy"), "matrix")[
            "ecosystems"
        ] = [""]
        self.assert_check_fails(self.check_matrix, testing)

    def test_a_dropped_axis_value_fails(self) -> None:
        """A matrix running the maven lane only fails the check."""
        testing = mutated(load_workflow(TESTING))
        section(section(job_of(testing, CASES_JOB), "strategy"), "matrix")[
            "lane"
        ] = ["maven"]
        self.assert_check_fails(self.check_matrix, testing)

    def test_a_scanner_off_the_policy_fails(self) -> None:
        """A scanner gating always fails the check."""
        testing = mutated(load_workflow(TESTING))
        step = step_of(job_of(testing, CASES_JOB), GRYPE_STEP)
        with_of(step)["gate-when"] = "always"
        self.assert_check_fails(self.check_scanner, testing)

    def test_a_drifted_fail_on_default_fails(self) -> None:
        """A lane whose grype_fail_on default moved fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        call_inputs(workflow)["grype_fail_on"]["default"] = "high"
        self.assert_check_fails(self.check_fail_on_default, workflow)

    def test_a_scan_before_detection_fails(self) -> None:
        """The scan moved ahead of detection fails the check."""
        testing = mutated(load_workflow(TESTING))
        job = job_of(testing, CASES_JOB)
        steps = steps_of(job)
        steps.insert(0, steps.pop(step_index(job, GRYPE_STEP)))
        self.assert_check_fails(self.check_order, testing)


if __name__ == "__main__":
    unittest.main()
