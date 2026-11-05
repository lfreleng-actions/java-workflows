# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Contract tests for the Grype gate policy wiring of both verify lanes.

The fixtures cannot exercise this wiring without a change to their
dependency files, so these tests hold it in place:

- the six grype_* policy inputs exist with the agreed defaults, and
  each reaches grype-scan-action under its own name, with the sidecar
  path and at the pin the lanes share;
- gerrit-validate's input check accepts each allowed value and rejects
  a typo, run as extracted from the workflows;
- the detection step runs dependency-change-action at its pin in a
  dependency-change job of its own, which runs nothing from the
  project, with the lane's preset and extra patterns over the whole
  repository, after the checkout and before the sidecar upload; the
  job, not the step, runs only under grype_gate_when:
  dependencies-changed with the SBOM on, so any other call skips it and
  the Grype job waits for nothing but the build;
- that job's actions/checkout holds the parent of HEAD, without which
  every pull request would be unresolved and gate;
- the sidecar travels in an artefact of its own, uploaded only when
  written, and no artefact the build job writes carries one;
- the Grype job downloads the SBOM and the sidecar each by its upload's
  ID, each into a directory of its own, and reads both from there, so
  no artefact uploaded under a reused name, and nothing inside the SBOM
  artefact, can pass for either;
- the lanes publish the gate's verdict, and testing.yaml runs the
  unresolved path against a pinned fixture and the resolved path
  against this repository's fixtures, each read by a check job;
- no symbolic link or submodule sits in this repository's tree,
  without which the resolved lanes could report unresolved;
- testing.yaml's gate-verdict-cases job runs dependency-change-action
  and grype-scan-action at the lanes' pins with the lanes' own inputs,
  on a known change per lane and case, with the verdict each case
  expects fixed in the matrix.

Each structural check is a method taking the workflow it judges; the
positive tests hand it the real workflows, the negative tests a copy
with one thing wrong, and expect it to fail.
"""

from __future__ import annotations

import copy
import datetime
import re
import subprocess
import unittest
from typing import Any, ClassVar, cast

from guards import needs_runner_tools, run_script
from helpers import (
    CHECKOUT_ACTIONS,
    GATE_VALIDATE,
    GRADLE,
    MAVEN,
    TESTING,
    ContractCase,
    Job,
    Step,
    Verdict,
    Workflow,
    find_step,
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

DETECT_PIN = "257928b15e4e6a5cc5a888435be59b058055c4e1"
DETECT_ACTION = "lfreleng-actions/dependency-change-action"
DETECT_USES = f"{DETECT_ACTION}@{DETECT_PIN}"
# The pin with its version comment, as the workflow text must hold it.
DETECT_LINE = f"uses: {DETECT_USES}  # v0.0.1"
GRYPE_PIN = "5c81b23afb2ea771b2d247807a12d90783328675"
GRYPE_USES = f"lfreleng-actions/grype-scan-action@{GRYPE_PIN}"

DETECT_JOB = "dependency-change"
# The condition on the detection job, as the literal workflow text.
DETECT_IF = (
    "inputs.sbom_enabled && inputs.grype_enabled"
    " && inputs.grype_gate_when == 'dependencies-changed'"
)
DETECT_STEP = "Detect dependency changes"
UPLOAD_STEP = "Upload dependency-change sidecar"
DOWNLOAD_STEP = "Download dependency-change sidecar"
SBOM_UPLOAD_STEP = "Upload SBOM artifacts"
SBOM_DOWNLOAD_STEP = "Download SBOM artefact"
GRYPE_STEP = "Grype audit SBOM"
SIDECAR = "dependency-change.json"
# Where each download lands, and where the audit step reads each file.
SIDECAR_DIR = "dependency-change"
SBOM_DIR = "sbom"
CASES_JOB = "gate-verdict-cases"
SUFFIX = "${{ inputs.artifact_suffix }}"

# What each preset watches beyond its dependency files: a -D property
# in jvm.config can select a Maven dependency version; any Gradle
# script file can declare a plugin or dependency the preset does not
# name, such as a convention script a subproject applies.
EXTRA_PATTERNS = {
    "maven": ".mvn/jvm.config",
    "gradle": "*.gradle\n*.gradle.kts",
}

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

# What the detection job may run: the runner hardening, the checkouts,
# the Gerrit submodule guard, the detection and its upload.
DETECT_JOB_ACTIONS = (
    "lfreleng-actions/harden-runner-block-action",
    "step-security/harden-runner",
    *CHECKOUT_ACTIONS,
    DETECT_ACTION,
    "actions/upload-artifact",
)
INIT_STEP = "Initialise Gerrit change submodules"

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
        """Fail unless the scanner is pinned and reads both files in place."""
        grype = step_of(job_of(workflow, "grype"), GRYPE_STEP)
        passed = with_of(grype)
        self.assertEqual(
            text(passed.get("dependency-change-manifest")),
            f"{SIDECAR_DIR}/{SIDECAR}",
            f"'{GRYPE_STEP}' must read the sidecar from its download",
        )
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

    def test_the_scanner_is_pinned_and_reads_the_downloads(self) -> None:
        """Each lane's scanner is at the shared pin over both downloads."""
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

    def test_a_sidecar_read_from_elsewhere_fails(self) -> None:
        """A scanner reading the sidecar from the SBOM directory fails."""
        workflow = mutated(load_workflow(MAVEN))
        step = step_of(job_of(workflow, "grype"), GRYPE_STEP)
        with_of(step)["dependency-change-manifest"] = f"{SBOM_DIR}/{SIDECAR}"
        self.assert_check_fails(self.check_scanner, workflow)


class GateInputValidation(ContractCase):
    """The gate input validation, run as extracted from each lane."""

    scripts: ClassVar[dict[str, str]] = {}

    @classmethod
    def setUpClass(cls) -> None:
        """Extract each lane's validation step once."""
        super().setUpClass()
        cls.scripts = {
            lane: run_of(load_workflow(lane), "gerrit-validate", GATE_VALIDATE)
            for lane in LANES
        }

    def validate(
        self,
        lane: str,
        gate_when: str = "always",
        policy: str = "declared",
        transitive: str = "critical",
        days: str = "",
        start: str = "",
    ) -> Verdict:
        """Run the step with one value set and the rest at their defaults."""
        return run_script(
            self.scripts[lane],
            {
                "GATE_WHEN": gate_when,
                "DEPENDENCY_POLICY": policy,
                "TRANSITIVE_FAIL_ON": transitive,
                "WINDOW_DAYS": days,
                "WINDOW_START": start,
            },
        )

    def test_the_step_runs_on_every_call(self) -> None:
        """The validation step has no condition."""
        for lane in LANES:
            with self.subTest(lane=lane):
                step = step_of(
                    job_of(load_workflow(lane), "gerrit-validate"),
                    GATE_VALIDATE,
                )
                self.assertEqual(
                    text(step.get("if")),
                    "",
                    f"{lane}: '{GATE_VALIDATE}' must run on every call",
                )

    @needs_runner_tools
    def test_defaults_pass(self) -> None:
        """The defaults pass."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.assert_passes(self.validate(lane), "defaults")

    @needs_runner_tools
    def test_gate_when(self) -> None:
        """grype_gate_when takes its two values and nothing else."""
        for lane in LANES:
            for value in ("always", "dependencies-changed"):
                with self.subTest(lane=lane, value=value):
                    self.assert_passes(
                        self.validate(lane, gate_when=value),
                        f"grype_gate_when '{value}'",
                    )
            for value in (
                "",
                "Always",
                "dependencies_changed",
                "never",
                "always\n::warning::injected",
            ):
                with self.subTest(lane=lane, value=value):
                    self.assert_fails(
                        self.validate(lane, gate_when=value),
                        f"grype_gate_when '{value}' rejected",
                    )

    @needs_runner_tools
    def test_dependency_policy(self) -> None:
        """grype_dependency_policy takes its two values and nothing else."""
        for lane in LANES:
            for value in ("all", "declared"):
                with self.subTest(lane=lane, value=value):
                    self.assert_passes(
                        self.validate(lane, policy=value),
                        f"grype_dependency_policy '{value}'",
                    )
            for value in ("", "direct", "Declared", "all declared"):
                with self.subTest(lane=lane, value=value):
                    self.assert_fails(
                        self.validate(lane, policy=value),
                        f"grype_dependency_policy '{value}' rejected",
                    )

    @needs_runner_tools
    def test_transitive_fail_on(self) -> None:
        """grype_transitive_fail_on takes a severity and nothing else."""
        for lane in LANES:
            for value in (
                "none",
                "negligible",
                "low",
                "medium",
                "high",
                "critical",
            ):
                with self.subTest(lane=lane, value=value):
                    self.assert_passes(
                        self.validate(lane, transitive=value),
                        f"grype_transitive_fail_on '{value}'",
                    )
            for value in ("", "Critical", "moderate", "high,critical"):
                with self.subTest(lane=lane, value=value):
                    self.assert_fails(
                        self.validate(lane, transitive=value),
                        f"grype_transitive_fail_on '{value}' rejected",
                    )

    @needs_runner_tools
    def test_remediation_window_days(self) -> None:
        """grype_remediation_window_days takes a whole number or nothing."""
        for lane in LANES:
            for value in ("", "0", "7", "30", "365"):
                with self.subTest(lane=lane, value=value):
                    self.assert_passes(
                        self.validate(lane, days=value),
                        f"grype_remediation_window_days '{value}'",
                    )
            for value in ("-1", "7.5", "7d", " 7", "seven"):
                with self.subTest(lane=lane, value=value):
                    self.assert_fails(
                        self.validate(lane, days=value),
                        f"grype_remediation_window_days '{value}' rejected",
                    )

    # 0000-01-01: GNU date accepts year zero, the action's ISO parser
    # does not, so it must fail here rather than after the build.
    START_PASSES = ("0001-01-01", "2026-01-01", "2024-02-29", "2099-12-31")
    START_FAILS = (
        "2026-1-1",
        "20260101",
        "01-01-2026",
        "2026-02-30",
        "2026-13-01",
        "0000-01-01",
        "0000-12-31",
        "2026-01-01T00:00:00Z",
        "yesterday",
        "2026-01-01\n::warning::injected",
    )

    def test_the_date_cases_agree_with_iso_8601(self) -> None:
        """The date data itself: each pass is a calendar date, no fail is.

        A date here is the extended ``YYYY-MM-DD`` form that names a day
        of the proleptic Gregorian calendar from year 1 on, as the
        action's parser reads it.
        """
        for value in self.START_PASSES:
            with self.subTest(value=value):
                self.assertTrue(self.is_iso_date(value), f"{value!r}")
        for value in self.START_FAILS:
            with self.subTest(value=value):
                self.assertFalse(self.is_iso_date(value), f"{value!r}")

    @staticmethod
    def is_iso_date(value: str) -> bool:
        """Return whether ``value`` is an extended-form calendar date."""
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value) is None:
            return False
        try:
            datetime.date.fromisoformat(value)
        except ValueError:
            return False
        return True

    @needs_runner_tools
    def test_remediation_window_start(self) -> None:
        """grype_remediation_window_start takes a full ISO date or nothing."""
        for lane in LANES:
            for value in ("", *self.START_PASSES):
                with self.subTest(lane=lane, value=value):
                    self.assert_passes(
                        self.validate(lane, start=value),
                        f"grype_remediation_window_start '{value}'",
                    )
            for value in self.START_FAILS:
                with self.subTest(lane=lane, value=value):
                    verdict = self.validate(lane, start=value)
                    self.assert_fails(
                        verdict,
                        f"grype_remediation_window_start '{value}' rejected",
                    )

    @needs_runner_tools
    def test_no_line_break_starts_a_workflow_command(self) -> None:
        """An injected line break never reaches the log as a command."""
        for lane in LANES:
            for field, value in (
                ("gate_when", "always\n::warning::injected"),
                ("start", "2026-01-01\n::warning::injected"),
            ):
                with self.subTest(lane=lane, field=field):
                    verdict = self.validate(lane, **{field: value})
                    self.assert_fails(verdict, f"{field} with a line break")
                    self.assertFalse(
                        verdict.warned(),
                        f"{lane}: the gate validation let a line break"
                        " start a workflow command",
                    )


class DetectionStep(ContractCase):
    """The detection step: its pin, inputs and place in the job."""

    def check_pin_in_text(self, path: str) -> None:
        """Fail unless the file runs the detector once, pin and comment."""
        source = read_text(path)
        self.assertIn(
            DETECT_LINE, source, f"{path}: no step runs {DETECT_LINE}"
        )
        self.assertEqual(
            source.count(f"{DETECT_ACTION}@"),
            1,
            f"{path}: dependency-change-action must appear once",
        )

    def check_step(self, workflow: Workflow, preset: str) -> None:
        """Fail unless the step runs the detector with the lane's inputs."""
        job = job_of(workflow, DETECT_JOB)
        step = find_step(job, DETECT_STEP)
        self.assertIsNotNone(
            step, f"the {DETECT_JOB} job has no '{DETECT_STEP}' step"
        )
        assert step is not None
        self.assertEqual(uses_of(step), DETECT_USES, f"'{DETECT_STEP}' uses")
        passed = with_of(step)
        want = {
            "ecosystems": preset,
            "patterns": EXTRA_PATTERNS[preset],
            "output": SIDECAR,
            # Repository-wide: a Maven parent chain or a Gradle included
            # build crosses directory boundaries path_prefix cannot
            # follow.
            "path-prefix": ".",
            "gerrit-refspec": "${{ inputs.gerrit_refspec }}",
        }
        got = {field: text(passed.get(field)) for field in want}
        self.assertEqual(got, want, f"'{DETECT_STEP}' with:")
        # The condition sits on the job; a step condition as well would
        # let the two drift apart.
        self.assertEqual(
            text(step.get("if")),
            "",
            f"'{DETECT_STEP}' must carry no condition of its own",
        )

    def check_order(self, workflow: Workflow) -> None:
        """Fail unless detection follows the checkouts and precedes the upload.

        After every checkout, so HEAD is the change; before the upload,
        so the sidecar is there to carry.
        """
        job = job_of(workflow, DETECT_JOB)
        detect = step_index(job, DETECT_STEP)
        checkout = last_checkout(job)
        upload = step_index(job, UPLOAD_STEP)
        self.assertTrue(
            checkout != -1 and upload != -1 and checkout < detect < upload,
            f"'{DETECT_STEP}' (step {detect}) must follow the last checkout"
            f" ({checkout}) and precede '{UPLOAD_STEP}' ({upload})",
        )

    def check_not_elsewhere(self, workflow: Workflow) -> None:
        """Fail if the build or repository-metadata job detects.

        The build job runs the project's own code; repository-metadata
        runs on every call, and the Grype job would then wait for it.
        """
        for job_id in ("build", "repository-metadata"):
            self.assertEqual(
                step_index(job_of(workflow, job_id), DETECT_STEP),
                -1,
                f"the {job_id} job must not run '{DETECT_STEP}'",
            )

    def test_the_pin_appears_once_with_its_comment(self) -> None:
        """Each lane holds the pinned uses: line, once, with its comment."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_pin_in_text(lane)

    def test_the_step_takes_the_lanes_inputs(self) -> None:
        """Each lane's step runs the detector with the lane's inputs."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_step(load_workflow(lane), PRESETS[lane])

    def test_the_step_sits_between_checkout_and_upload(self) -> None:
        """Each lane detects after its checkouts and before its upload."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_order(load_workflow(lane))

    def test_no_other_job_detects(self) -> None:
        """Neither the build nor the metadata job runs the detector."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_not_elsewhere(load_workflow(lane))

    def test_a_condition_on_the_step_fails(self) -> None:
        """The job's condition duplicated onto the step fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        step_of(job_of(workflow, DETECT_JOB), DETECT_STEP)["if"] = DETECT_IF
        self.assert_check_fails(self.check_step, workflow, "maven")

    def test_a_narrowed_prefix_fails(self) -> None:
        """A detector held to a path prefix fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        step = step_of(job_of(workflow, DETECT_JOB), DETECT_STEP)
        with_of(step)["path-prefix"] = "${{ inputs.path_prefix }}"
        self.assert_check_fails(self.check_step, workflow, "gradle")

    def test_the_other_presets_patterns_fail(self) -> None:
        """A lane watching the other preset's patterns fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        step = step_of(job_of(workflow, DETECT_JOB), DETECT_STEP)
        with_of(step)["patterns"] = EXTRA_PATTERNS["gradle"]
        self.assert_check_fails(self.check_step, workflow, "maven")

    def test_detection_before_the_checkout_fails(self) -> None:
        """Detection moved ahead of the checkout fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        steps = steps_of(job_of(workflow, DETECT_JOB))
        step = steps.pop(step_index(job_of(workflow, DETECT_JOB), DETECT_STEP))
        steps.insert(0, step)
        self.assert_check_fails(self.check_order, workflow)

    def test_detection_after_the_upload_fails(self) -> None:
        """Detection moved behind the upload fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        steps = steps_of(job_of(workflow, DETECT_JOB))
        step = steps.pop(step_index(job_of(workflow, DETECT_JOB), DETECT_STEP))
        steps.append(step)
        self.assert_check_fails(self.check_order, workflow)

    def test_detection_in_the_build_job_fails(self) -> None:
        """A detection step copied into the build job fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        step = step_of(job_of(workflow, DETECT_JOB), DETECT_STEP)
        steps_of(job_of(workflow, "build")).append(copy.deepcopy(step))
        self.assert_check_fails(self.check_not_elsewhere, workflow)


class DetectionJob(ContractCase):
    """The dependency-change job: its condition, steps and checkout."""

    def check_condition(self, workflow: Workflow) -> None:
        """Fail unless the job runs only when a scan can consume the result.

        Without the SBOM no Grype job runs, and under 'always' the scan
        ignores the sidecar. On the job, so every other call skips it
        outright and the Grype job's wait for it ends at once.
        """
        self.assertEqual(
            text(job_of(workflow, DETECT_JOB).get("if")),
            DETECT_IF,
            f"the {DETECT_JOB} job's condition",
        )

    def check_steps(self, workflow: Workflow) -> None:
        """Fail if the job runs anything from the project.

        No build, SBOM or setup action: only the runner hardening, the
        checkouts, the Gerrit submodule guard, the detection and its
        upload.
        """
        stray = [
            text(step.get("name"))
            for step in steps_of(job_of(workflow, DETECT_JOB))
            if not is_action(step, *DETECT_JOB_ACTIONS)
            and text(step.get("name")) != INIT_STEP
        ]
        self.assertEqual(
            stray, [], f"the {DETECT_JOB} job runs other steps: {stray}"
        )

    def check_checkout_depth(self, workflow: Workflow) -> None:
        """Fail unless the job's actions/checkout holds the parent of HEAD.

        The parent of HEAD is the base on a pull request: 2 holds it, as
        does 0, the whole history; 1, or the default of 1, does not.
        """
        depths = [
            text(with_of(step).get("fetch-depth", "unset"))
            for step in steps_of(job_of(workflow, DETECT_JOB))
            if is_action(step, "actions/checkout")
        ]
        self.assertNotEqual(
            depths, [], f"the {DETECT_JOB} job has no actions/checkout step"
        )
        for depth in depths:
            self.assertTrue(
                depth.isdigit() and depth != "1",
                f"the {DETECT_JOB} job's actions/checkout fetches depth"
                f" '{depth}'; dependency-change-action needs 2 or more",
            )

    def test_the_job_runs_only_under_the_policy(self) -> None:
        """Each lane's job carries the agreed condition."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_condition(load_workflow(lane))

    def test_the_job_runs_nothing_from_the_project(self) -> None:
        """Each lane's job runs only the allowed steps."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_steps(load_workflow(lane))

    def test_the_checkout_holds_the_parent(self) -> None:
        """Each lane's checkout fetches at least two commits."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_checkout_depth(load_workflow(lane))

    def test_a_job_without_its_condition_fails(self) -> None:
        """The job with its condition deleted fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        del job_of(workflow, DETECT_JOB)["if"]
        self.assert_check_fails(self.check_condition, workflow)

    def test_a_job_under_a_wider_condition_fails(self) -> None:
        """The job gated on the SBOM alone fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        job_of(workflow, DETECT_JOB)["if"] = "inputs.sbom_enabled"
        self.assert_check_fails(self.check_condition, workflow)

    def test_a_build_step_in_the_job_fails(self) -> None:
        """A build action appended to the job fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        build = next(
            step
            for step in steps_of(job_of(workflow, "build"))
            if is_action(step, "lfreleng-actions/maven-build-action")
        )
        steps_of(job_of(workflow, DETECT_JOB)).append(copy.deepcopy(build))
        self.assert_check_fails(self.check_steps, workflow)

    def test_a_run_step_in_the_job_fails(self) -> None:
        """A plain run step in the job fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        step: Step = {"name": "Warm the cache", "run": "./gradlew help"}
        steps_of(job_of(workflow, DETECT_JOB)).insert(2, step)
        self.assert_check_fails(self.check_steps, workflow)

    def test_a_shallow_checkout_fails(self) -> None:
        """A checkout at depth 1, or with no depth, fails the check."""
        for depth in ("1", None):
            with self.subTest(depth=depth):
                workflow = mutated(load_workflow(MAVEN))
                for step in steps_of(job_of(workflow, DETECT_JOB)):
                    if is_action(step, "actions/checkout"):
                        if depth is None:
                            with_of(step).pop("fetch-depth", None)
                        else:
                            with_of(step)["fetch-depth"] = int(depth)
                self.assert_check_fails(self.check_checkout_depth, workflow)

    def test_a_job_without_a_checkout_fails(self) -> None:
        """A job whose actions/checkout is gone fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        job = job_of(workflow, DETECT_JOB)
        job["steps"] = [
            step
            for step in steps_of(job)
            if not is_action(step, "actions/checkout")
        ]
        self.assert_check_fails(self.check_checkout_depth, workflow)


class SidecarArtefact(ContractCase):
    """The sidecar's upload, the job output and the Grype job's needs."""

    def check_upload(self, workflow: Workflow, preset: str) -> None:
        """Fail unless the sidecar uploads alone, only when written."""
        step = step_of(job_of(workflow, DETECT_JOB), UPLOAD_STEP)
        passed = with_of(step)
        got = {
            "if": text(step.get("if")),
            "name": text(passed.get("name")),
            "path": text(passed.get("path")),
            "if-no-files-found": text(passed.get("if-no-files-found")),
        }
        want = {
            # On the action's manifest output, empty when unresolved:
            # the step then skips, rather than failing on a file that
            # is not there, and the job output below reads false.
            "if": "steps.dependency-change.outputs.manifest != ''",
            "name": f"dependency-change-{preset}{SUFFIX}",
            "path": SIDECAR,
            "if-no-files-found": "error",
        }
        self.assertEqual(got, want, f"'{UPLOAD_STEP}'")

    def check_job_output(self, workflow: Workflow) -> None:
        """Fail unless the job publishes the upload's artifact-id.

        The ID of the upload, not a flag: the Grype job downloads by it,
        so a same-name artefact from the build job cannot stand in.
        """
        job = job_of(workflow, DETECT_JOB)
        upload_id = text(step_of(job, UPLOAD_STEP).get("id")) or "?"
        self.assertEqual(
            text(outputs_of(job).get("dependency_change_artifact_id")),
            f"${{{{ steps.{upload_id}.outputs.artifact-id }}}}",
            f"{DETECT_JOB}'s dependency_change_artifact_id must be the"
            f" artifact-id output of '{UPLOAD_STEP}'",
        )

    def check_grype_needs(self, workflow: Workflow) -> None:
        """Fail unless the Grype job needs build and detection, no more."""
        grype = job_of(workflow, "grype")
        self.assertTrue(
            needs_mention(grype, DETECT_JOB),
            f"the grype job must need {DETECT_JOB}",
        )
        self.assertFalse(
            needs_mention(grype, "repository-metadata"),
            "the grype job must not need repository-metadata, which runs"
            " on every call",
        )
        self.assertTrue(
            needs_mention(grype, "build"),
            "the grype job must still need build",
        )

    def check_no_other_carrier(self, workflow: Workflow) -> None:
        """Fail if an upload other than the sidecar's carries the sidecar.

        The SBOM in particular, whose job ran the project's build.
        """
        carriers = [
            text(step.get("name"))
            for job in jobs_of(workflow).values()
            for step in steps_of(job)
            if is_action(step, "actions/upload-artifact")
            and text(step.get("name")) != UPLOAD_STEP
            and SIDECAR in text(with_of(step).get("path"))
        ]
        self.assertEqual(
            carriers, [], f"{SIDECAR} also travels in: {carriers}"
        )

    def test_the_upload(self) -> None:
        """Each lane uploads the sidecar as agreed."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_upload(load_workflow(lane), PRESETS[lane])

    def test_the_job_output(self) -> None:
        """Each lane's detection job publishes its upload's ID."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_job_output(load_workflow(lane))

    def test_the_grype_needs(self) -> None:
        """Each lane's Grype job needs build and detection only."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_grype_needs(load_workflow(lane))

    def test_no_other_upload_carries_the_sidecar(self) -> None:
        """No other artefact of either lane holds the sidecar."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_no_other_carrier(load_workflow(lane))

    def test_an_unconditional_upload_fails(self) -> None:
        """An upload that runs whatever the detector wrote fails."""
        workflow = mutated(load_workflow(MAVEN))
        del step_of(job_of(workflow, DETECT_JOB), UPLOAD_STEP)["if"]
        self.assert_check_fails(self.check_upload, workflow, "maven")

    def test_an_unsuffixed_artefact_fails(self) -> None:
        """An artefact name without the suffix fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        step = step_of(job_of(workflow, DETECT_JOB), UPLOAD_STEP)
        with_of(step)["name"] = "dependency-change-gradle"
        self.assert_check_fails(self.check_upload, workflow, "gradle")

    def test_a_flag_as_the_job_output_fails(self) -> None:
        """A job output that is a flag, not the upload's ID, fails."""
        workflow = mutated(load_workflow(MAVEN))
        outputs_of(job_of(workflow, DETECT_JOB))[
            "dependency_change_artifact_id"
        ] = "${{ steps.dependency-change.outputs.manifest != '' }}"
        self.assert_check_fails(self.check_job_output, workflow)

    def test_grype_needing_repository_metadata_fails(self) -> None:
        """A Grype job needing repository-metadata, not detection, fails."""
        workflow = mutated(load_workflow(GRADLE))
        job_of(workflow, "grype")["needs"] = ["build", "repository-metadata"]
        self.assert_check_fails(self.check_grype_needs, workflow)

    def test_grype_without_build_fails(self) -> None:
        """A Grype job no longer needing build fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        job_of(workflow, "grype")["needs"] = [DETECT_JOB]
        self.assert_check_fails(self.check_grype_needs, workflow)

    def test_a_sidecar_in_the_sbom_artefact_fails(self) -> None:
        """A sidecar packed into the SBOM artefact fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        step = step_of(job_of(workflow, "build"), SBOM_UPLOAD_STEP)
        with_of(step)["path"] = f"{text(with_of(step).get('path'))}\n{SIDECAR}"
        self.assert_check_fails(self.check_no_other_carrier, workflow)


class ArtefactDownloads(ContractCase):
    """The Grype job's two downloads, each by ID into its own directory."""

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

    def expected_download(self, name: str) -> dict[str, str]:
        """Return the fields each download must carry."""
        sidecar_id = (
            f"needs.{DETECT_JOB}.outputs.dependency_change_artifact_id"
        )
        sbom_id = "needs.build.outputs.sbom_artifact_id"
        if name == DOWNLOAD_STEP:
            return {
                # Skipped when the dependency-change job uploaded
                # nothing; an ID that resolves to no artefact fails the
                # download, and the job.
                "if": f"{sidecar_id} != ''",
                # By the exact upload, never by a name another job
                # could reuse.
                "artifact-ids": f"${{{{ {sidecar_id} }}}}",
                # Into a directory of its own, so nothing the SBOM
                # artefact holds can pass for it, and with
                # merge-multiple, which drops the artefact-name level a
                # download by ID adds.
                "merge-multiple": "true",
                "name": "",
                "path": SIDECAR_DIR,
            }
        return {
            # The grype job runs only when the SBOM uploaded, so the
            # download needs no condition of its own.
            "if": "",
            "artifact-ids": f"${{{{ {sbom_id} }}}}",
            "merge-multiple": "true",
            "name": "",
            "path": SBOM_DIR,
        }

    def check_download(self, workflow: Workflow, name: str) -> None:
        """Fail unless download ``name`` goes by ID into place, pre-scan."""
        grype = job_of(workflow, "grype")
        step = step_of(grype, name)
        passed = with_of(step)
        got = {
            "if": text(step.get("if")),
            "artifact-ids": text(passed.get("artifact-ids")),
            "merge-multiple": text(passed.get("merge-multiple")),
            "name": text(passed.get("name")),
            "path": text(passed.get("path")),
        }
        self.assertEqual(got, self.expected_download(name), f"'{name}'")
        index = step_index(grype, name)
        scan = step_index(grype, GRYPE_STEP)
        self.assertTrue(
            index != -1 and scan != -1 and index < scan,
            f"'{name}' must precede '{GRYPE_STEP}'",
        )

    def check_no_named_download(self, workflow: Workflow) -> None:
        """Fail if any download in the Grype job resolves a name."""
        named = [
            text(step.get("name"))
            for step in steps_of(job_of(workflow, "grype"))
            if is_action(step, "actions/download-artifact")
            and with_of(step).get("name") is not None
        ]
        self.assertEqual(
            named, [], f"the grype job downloads by name in: {named}"
        )

    def test_the_build_publishes_its_sbom_upload(self) -> None:
        """Each lane's build job publishes the SBOM upload's ID."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_sbom_output(load_workflow(lane))

    def test_both_downloads(self) -> None:
        """Each lane downloads the sidecar and the SBOM as agreed."""
        for lane in LANES:
            for name in (DOWNLOAD_STEP, SBOM_DOWNLOAD_STEP):
                with self.subTest(lane=lane, step=name):
                    self.check_download(load_workflow(lane), name)

    def test_no_download_goes_by_name(self) -> None:
        """No download in either lane's Grype job resolves a name."""
        for lane in LANES:
            with self.subTest(lane=lane):
                self.check_no_named_download(load_workflow(lane))

    def test_a_download_by_name_fails(self) -> None:
        """The sidecar download by artefact name fails both checks."""
        workflow = mutated(load_workflow(MAVEN))
        step = step_of(job_of(workflow, "grype"), DOWNLOAD_STEP)
        passed = with_of(step)
        del passed["artifact-ids"]
        passed["name"] = f"dependency-change-maven{SUFFIX}"
        self.assert_check_fails(self.check_download, workflow, DOWNLOAD_STEP)
        self.assert_check_fails(self.check_no_named_download, workflow)

    def test_a_shared_download_directory_fails(self) -> None:
        """The sidecar downloaded into the SBOM directory fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        step = step_of(job_of(workflow, "grype"), DOWNLOAD_STEP)
        with_of(step)["path"] = SBOM_DIR
        self.assert_check_fails(self.check_download, workflow, DOWNLOAD_STEP)

    def test_an_unconditional_sidecar_download_fails(self) -> None:
        """A sidecar download with no condition fails the check."""
        workflow = mutated(load_workflow(MAVEN))
        del step_of(job_of(workflow, "grype"), DOWNLOAD_STEP)["if"]
        self.assert_check_fails(self.check_download, workflow, DOWNLOAD_STEP)

    def test_a_download_after_the_scan_fails(self) -> None:
        """The SBOM download moved behind the scan fails the check."""
        workflow = mutated(load_workflow(GRADLE))
        grype = job_of(workflow, "grype")
        steps = steps_of(grype)
        steps.append(steps.pop(step_index(grype, SBOM_DOWNLOAD_STEP)))
        self.assert_check_fails(
            self.check_download, workflow, SBOM_DOWNLOAD_STEP
        )

    def test_a_flag_as_the_sbom_output_fails(self) -> None:
        """A build output naming the step, not its artifact-id, fails."""
        workflow = mutated(load_workflow(MAVEN))
        outputs_of(job_of(workflow, "build"))["sbom_artifact_id"] = (
            "${{ steps.upload-sbom.outcome }}"
        )
        self.assert_check_fails(self.check_sbom_output, workflow)


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


def readers_of(testing: Workflow, lane: str) -> list[str]:
    """Return the jobs needing ``lane`` that read its grype_gate_active."""
    wanted = f"needs.{lane}.outputs.grype_gate_active"
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
    repository, at the run's own commit, so the detector writes a
    sidecar the check job holds the gate to. Each lane's check job reads
    the verdict the lane publishes.
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
            self.assertNotEqual(
                readers_of(testing, lane),
                [],
                f"no job needing {lane} reads its grype_gate_active",
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

    The resolved lanes' check requires the sidecar artefact, on the
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

    The job needs both resolved lanes (for their SBOMs), runs the
    detector at the lanes' pin with the lanes' inputs over a scratch
    repository with an explicit base, and the scanner at the lanes' pin
    with the lanes' policy and manifest path; its matrix fixes each
    case's expected verdict.
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
            "uses": DETECT_USES,
            "ecosystems": "${{ matrix.ecosystems }}",
            "patterns": "${{ matrix.patterns }}",
            "base": "${{ steps.scratch.outputs.base }}",
            "output": SIDECAR,
            "path-prefix": ".",
        }
        got = {"uses": uses_of(step)}
        got.update(
            (field, text(passed.get(field)))
            for field in want
            if field != "uses"
        )
        self.assertEqual(got, want, f"{CASES_JOB}'s '{DETECT_STEP}'")

    def check_matrix(self, testing: Workflow) -> None:
        """Fail unless the matrix carries the lanes' inputs and verdicts."""
        job = job_of(testing, CASES_JOB)
        rows = include_rows(job)
        for preset, extra in EXTRA_PATTERNS.items():
            row = row_where(rows, "lane", preset)
            self.assertEqual(
                (text(row.get("ecosystems")), text(row.get("patterns"))),
                (preset, extra),
                f"{CASES_JOB}'s {preset} row",
            )
        for case, expected in (("unchanged", "false"), ("changed", "true")):
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
            matrix_axis(job, "case"), ["unchanged", "changed"], "matrix.case"
        )

    def check_scanner(self, testing: Workflow) -> None:
        """Fail unless the scanner runs with the lanes' policy as literals."""
        step = step_of(job_of(testing, CASES_JOB), GRYPE_STEP)
        passed = with_of(step)
        want = {
            "gate-when": "dependencies-changed",
            "dependency-change-manifest": SIDECAR,
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
            DETECT_LINE,
            read_text(TESTING),
            f"{TESTING}: no step runs {DETECT_LINE}",
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
        del with_of(step)["base"]
        self.assert_check_fails(self.check_detector, testing)

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
        """A second maven row, overriding its patterns, fails the check."""
        testing = mutated(load_workflow(TESTING))
        include_of(job_of(testing, CASES_JOB)).append(
            {"lane": "maven", "ecosystems": "maven", "patterns": ""}
        )
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
