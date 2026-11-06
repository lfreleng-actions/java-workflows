# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Contract tests for what the self-test fixtures cannot exercise.

- the guard steps' accept and reject paths, run as extracted from the
  workflows, so a change to a guard shows up here; the merge lane's
  POM guard and POM location must match the verify lane's, while its
  environment guard does more and is tested on its own;
- the merge lane's input validation, including the branch its
  checkouts build, and its m2repo checks, whose reject paths guard the
  publish;
- the merge lane's coordinate check: prune keeps it on, and the
  testing.yaml job proving the rejection runs the lane's own pin;
- the merge lane's copy of maven-build-action's workspace placeholder
  expansion, against the vendored script at the pinned SHA;
- the Gerrit submodule initialisation, against a local change that
  adds a submodule, which a plain 'git submodule update' skips;
- the submodule wiring of every checkout in all three lanes;
- every lane's artifact_suffix, on every artefact name it chooses for
  an upload or a download, so a matrix of calls cannot cross them;
- every per-cell upload the compatibility checks read, which a re-run
  replaces, and every toolchain record, which waits for a successful
  build;
- the compatibility checks' reading of each cell's latest build job
  before its records, and latest-attempt-check.sh's verdicts on it;
- zizmor's impostor-commit ignores for the examples' placeholder SHA,
  which only an online run applies, against the examples themselves.

Each structural check takes the workflow it judges, so the negative
tests hand it a mutated copy and expect the assertion to fire.
"""

from __future__ import annotations

import copy
import json
import os
import re
import shlex
import subprocess
import tempfile
import time
import unittest
from collections.abc import Callable
from pathlib import Path

from guards import needs_runner_tools, run_script
from helpers import (
    BUDGET,
    CHECKOUT_ACTIONS,
    CLEAN,
    ENV_GUARD,
    EXPAND,
    GERRIT_CHECKOUT,
    GRADLE,
    INIT_STEP,
    LANDED,
    LOCATE,
    MAVEN,
    MERGE,
    MERGE_ENV_GUARD,
    POM_GUARD,
    STALE,
    SUFFIX_STEP,
    TESTING,
    VALIDATE,
    ContractCase,
    Verdict,
    Workflow,
    env_of,
    find_step,
    is_action,
    job_of,
    jobs_of,
    load_workflow,
    mappings,
    outputs_of,
    present,
    run_of,
    step_index,
    step_of,
    step_with_id,
    steps_of,
    text,
    uses_lines,
    uses_of,
    with_of,
)
from yaml_loading import ROOT, load_yaml, read_text

# The literal expression each checkout must pass, not a shell expansion.
WIRING = "${{ inputs.checkout_submodules }}"
LANES = (MAVEN, GRADLE, MERGE)

SBOM_STEP = "Generate SBOM"
SBOM_UPLOAD = "Upload SBOM artifacts"
M2REPO_DOWNLOAD = "Download the m2repo"
M2REPO_UPLOAD = "Upload the m2repo"
JUNIT_UPLOAD = "Upload JUnit reports"
RECORD = "Record the toolchain"
RECORD_UPLOAD = "Upload the toolchain record"
RECORD_IF = "${{ success() && inputs.artifact_suffix != '' }}"
RECORDED = "steps.toolchain.outcome == 'success'"
OVERWRITE = "${{ inputs.artifact_suffix != '' }}"
CELL_PATTERN = re.compile(r"\{([^}]+)\}-(?:maven|gradle)-\*")
PRUNE = "Prune unchanged SNAPSHOT metadata"
AGGREGATORS = ("compatibility-check", "compatibility-gradle-check")
READ_BUILDS = "Read each cell build"
ASSERT_CELLS = "Assert every cell"
JOBS_FILE = "${RUNNER_TEMP}/jobs.json"
LATEST_CHECK = ".github/scripts/latest-attempt-check.sh"

EXPAND_PIN = "1de87fd734620335eeae65933795f226c0d8a24e"
EXPAND_VENDORED = (
    ".github/scripts/vendor/maven-build-action/expand-workspace-vars.sh"
)
METADATA_ACTION = "lfreleng-actions/maven-snapshot-metadata-action"
GRYPE_ACTION = "lfreleng-actions/grype-scan-action"
ARTEFACT_ACTIONS = (
    "actions/upload-artifact",
    "actions/download-artifact",
    "lfreleng-actions/maven-build-action",
    "lfreleng-actions/gradle-build-action",
    GRYPE_ACTION,
)
SUFFIX = "${{ inputs.artifact_suffix }}"
NEEDS_PREFIX = "${{ needs."
STEPS_PREFIX = "${{ steps."
CLOSE = " }}"
ZIZMOR_CONFIG = ".github/zizmor.yml"
PLACEHOLDER = re.compile(r"@0{40}$")

SELF = "example-org/example-repo"
VERSION = "org/example/core/1.0.0-SNAPSHOT"
SNAPSHOT_JAR = f"{VERSION}/core-1.0.0-20260101.000000-1.jar"


class GuardCase(ContractCase):
    """A test case running one guard step extracted from a workflow.

    A test that runs the guard carries ``needs_runner_tools``: on the
    class where every test does, on each such method where structural
    tests sit beside them, which run on any host.
    """

    workflow = MAVEN
    job = "build"
    step = ""
    script = ""

    @classmethod
    def setUpClass(cls) -> None:
        """Extract the step's run block once for the class."""
        super().setUpClass()
        cls.script = run_of(load_workflow(cls.workflow), cls.job, cls.step)

    def run_guard(self, cwd: Path | None = None, **env: str) -> Verdict:
        """Run the extracted step with ``env`` and return its verdict."""
        return run_script(self.script, env, cwd=cwd)


@needs_runner_tools
class SbomPomGuard(GuardCase):
    """Build job: SBOM POM guard."""

    step = POM_GUARD

    def test_accepts_the_root_pom(self) -> None:
        """The default and each spelling of the root POM pass."""
        for pom in ("", "pom.xml", "./pom.xml", "././pom.xml"):
            with self.subTest(pom=pom):
                verdict = self.run_guard(MVN_POM_FILE=pom)
                self.assert_passes(verdict, f"POM guard accepts '{pom}'")

    def test_rejects_any_other_pom(self) -> None:
        """A POM in a subdirectory, under another name or as a directory fails.

        Each is one the SBOM cannot resolve.
        """
        for pom in ("core/pom.xml", "build-pom.xml", "pom.xml/"):
            with self.subTest(pom=pom):
                verdict = self.run_guard(MVN_POM_FILE=pom)
                self.assert_fails(verdict, f"POM guard rejects '{pom}'")

    def test_rejects_a_line_break(self) -> None:
        """A line break fails without starting a workflow command."""
        verdict = self.run_guard(MVN_POM_FILE="x\n::warning::injected")
        self.assert_fails(verdict, "POM guard rejects a line break")
        self.assertFalse(
            verdict.warned(),
            "POM guard let a line break start a workflow command",
        )


class SbomEnvironmentGuard(GuardCase):
    """Build job: SBOM environment guard."""

    step = ENV_GUARD

    @needs_runner_tools
    def test_accepts_names_the_sbom_can_reproduce(self) -> None:
        """Empty, an empty object and names the SBOM does not set pass."""
        for value in (
            "",
            "{}",
            '{"MAVEN_OPTS": "-Dx=y"}',
            '{"my_flag": "1"}',
            '{"_x": "1", "My_Flag2": "1"}',
        ):
            with self.subTest(value=value):
                verdict = self.run_guard(ENV_VARS=value)
                self.assert_passes(
                    verdict, f"environment guard accepts {value or 'empty'}"
                )

    @needs_runner_tools
    def test_rejects_other_shapes_and_reserved_names(self) -> None:
        """Anything but an object, and a name the SBOM step sets, fails."""
        for value in (
            "[]",
            '"text"',
            "not json",
            '{"MAVEN_ARGS": "-f x"}',
            '{"maven_args": "-f x"}',
            '{"JAVA_VERSION": "8"}',
            '{"MVN_OPTS": "-Dx"}',
        ):
            with self.subTest(value=value):
                verdict = self.run_guard(ENV_VARS=value)
                self.assert_fails(
                    verdict, f"environment guard rejects {value}"
                )

    @needs_runner_tools
    def test_rejects_names_unicode_case_mapping_reserves(self) -> None:
        """Names full Unicode case mapping turns into reserved ones fail.

        vars-to-env-action applies it: U+017F and U+0131 upper-case to S
        and I. Other non-identifiers fail too. The JSON escapes keep the
        test ASCII and the case locale-independent.
        """
        for value in (
            '{"maven_arg\\u017f": "-f x"}',
            '{"path_pref\\u0131x": "x"}',
            '{"": "x"}',
            '{"1ST": "x"}',
            '{"MY-FLAG": "x"}',
            '{"MY_FLAG\\nMAVEN_ARGS": "x"}',
        ):
            with self.subTest(value=value):
                verdict = self.run_guard(ENV_VARS=value)
                self.assert_fails(
                    verdict, f"environment guard rejects the name in {value}"
                )

    def test_long_s_upper_cases_to_maven_args(self) -> None:
        """The first Unicode case must be a bypass without the ASCII check.

        Otherwise it tests nothing: the action upper-cases with Python's
        str.upper(), which would export it as MAVEN_ARGS.
        """
        self.assertEqual("maven_arg\u017f".upper(), "MAVEN_ARGS")


@needs_runner_tools
class PomLocation(GuardCase):
    """Build job: POM location for metadata."""

    step = LOCATE

    def locate(self, label: str, prefix: str, pom: str, java: str) -> Verdict:
        """Run the step for the three inputs and expect a pass."""
        verdict = self.run_guard(
            PATH_PREFIX=prefix, MVN_POM_FILE=pom, JAVA_VERSION=java
        )
        self.assert_passes(verdict, label)
        return verdict

    def test_default_pom(self) -> None:
        """No POM input locates the path prefix."""
        verdict = self.locate("default POM", ".", "", "")
        self.assertEqual(verdict.value("metadata_path"), ".")

    def test_root_pom(self) -> None:
        """The root POM locates the path prefix."""
        verdict = self.locate("root POM", ".", "./pom.xml", "")
        self.assertEqual(verdict.value("metadata_path"), ".")

    def test_subdirectory_pom(self) -> None:
        """A POM in a subdirectory locates that directory."""
        verdict = self.locate("subdirectory POM", "repo", "core/pom.xml", "")
        self.assertEqual(verdict.value("metadata_path"), "repo/core")

    def test_unreadable_pom_without_java_version(self) -> None:
        """A POM under another name fails without a java_version to use."""
        verdict = self.run_guard(
            PATH_PREFIX=".", MVN_POM_FILE="build-pom.xml", JAVA_VERSION=""
        )
        self.assert_fails(verdict, "unreadable POM without java_version")

    def test_unreadable_pom_with_java_version(self) -> None:
        """A POM under another name passes when java_version is given."""
        verdict = self.locate(
            "unreadable POM with java_version", ".", "build-pom.xml", "17"
        )
        self.assertEqual(verdict.value("metadata_path"), ".")

    def test_line_break_in_path_prefix(self) -> None:
        """A line break in path_prefix fails."""
        verdict = self.run_guard(
            PATH_PREFIX="a\nb", MVN_POM_FILE="", JAVA_VERSION=""
        )
        self.assert_fails(verdict, "line break in path_prefix")


class MergeLaneGuardsMatchVerifyLane(ContractCase):
    """Merge lane: guards match the verify lane.

    The merge lane runs the POM guard and the POM location as the verify
    lane does, tested above through the verify lane's copies, so its own
    must not drift from them. The whole step is compared, since its if:,
    env: or shell: can break it as surely as its script. Its environment
    guard differs on purpose and is tested on its own.
    """

    def check_step_matches(
        self, maven: Workflow, merge: Workflow, step: str
    ) -> None:
        """Fail unless build step ``step`` is the same in both lanes."""
        self.assertEqual(
            step_of(job_of(maven, "build"), step),
            step_of(job_of(merge, "build"), step),
            f"{MERGE}: '{step}' differs from the verify lane's",
        )

    def test_pom_guard_matches(self) -> None:
        """The merge lane's POM guard is the verify lane's."""
        self.check_step_matches(
            load_workflow(MAVEN), load_workflow(MERGE), POM_GUARD
        )

    def test_pom_location_matches(self) -> None:
        """The merge lane's POM location is the verify lane's."""
        self.check_step_matches(
            load_workflow(MAVEN), load_workflow(MERGE), LOCATE
        )

    def test_a_drifted_condition_fails(self) -> None:
        """A merge lane POM guard with another if: fails the check."""
        merge = load_workflow(MERGE)
        step_of(job_of(merge, "build"), POM_GUARD)["if"] = "always()"
        self.assert_check_fails(
            self.check_step_matches, load_workflow(MAVEN), merge, POM_GUARD
        )

    def test_a_drifted_script_fails(self) -> None:
        """A merge lane POM location with another run: fails the check."""
        merge = load_workflow(MERGE)
        step_of(job_of(merge, "build"), LOCATE)["run"] += "\ntrue\n"
        self.assert_check_fails(
            self.check_step_matches, load_workflow(MAVEN), merge, LOCATE
        )

    def test_a_second_drifted_step_fails(self) -> None:
        """A second, drifted POM guard appended to the merge job fails.

        The first copy still matches the verify lane's; the check must
        not stop there and pass on it.
        """
        merge = load_workflow(MERGE)
        steps = steps_of(job_of(merge, "build"))
        drifted = copy.deepcopy(step_of(job_of(merge, "build"), POM_GUARD))
        drifted["if"] = "always()"
        steps.append(drifted)
        self.assert_check_fails(
            self.check_step_matches, load_workflow(MAVEN), merge, POM_GUARD
        )


class MergeEnvironmentGuard(GuardCase):
    """Merge lane: environment guard.

    The merge lane's environment guard does more than the verify lane's.
    The metadata fetch inherits the job's environment while the deploy
    step sets its own names, so a name either sets would give the two
    different reactors; that holds whether or not the SBOM runs. The
    SBOM's own names still apply only when it does.
    """

    workflow = MERGE
    step = MERGE_ENV_GUARD

    def check_runs_unconditionally(self, merge: Workflow) -> None:
        """Fail when the guard carries an if:, whatever sbom_enabled is."""
        step = step_of(job_of(merge, "build"), MERGE_ENV_GUARD)
        self.assertNotIn(
            "if",
            step,
            f"{MERGE}: the environment guard must run whatever sbom_enabled"
            " is",
        )

    def test_runs_whatever_sbom_enabled_is(self) -> None:
        """The guard has no condition."""
        self.check_runs_unconditionally(load_workflow(MERGE))

    def test_a_conditional_guard_fails(self) -> None:
        """A guard gated on the SBOM fails the check."""
        merge = load_workflow(MERGE)
        step_of(job_of(merge, "build"), MERGE_ENV_GUARD)["if"] = (
            "inputs.sbom_enabled"
        )
        self.assert_check_fails(self.check_runs_unconditionally, merge)

    @needs_runner_tools
    def test_accepts_names_neither_step_sets(self) -> None:
        """Empty, an empty object and free names pass with and without SBOM."""
        for sbom in ("true", "false"):
            for value in (
                "",
                "{}",
                '{"MAVEN_OPTS": "-Dx=y"}',
                '{"my_flag": "1"}',
            ):
                with self.subTest(sbom=sbom, value=value):
                    verdict = self.run_guard(ENV_VARS=value, SBOM_ENABLED=sbom)
                    self.assert_passes(
                        verdict,
                        f"merge guard (sbom {sbom}) accepts"
                        f" {value or 'empty'}",
                    )

    @needs_runner_tools
    def test_rejects_fetch_and_deploy_names_without_an_sbom(self) -> None:
        """Fetch/deploy parity: refused even without an SBOM.

        MAVEN_OPTS is not among them: neither step sets it, so both
        inherit one value.
        """
        for sbom in ("true", "false"):
            for value in (
                '{"MVN_PARAMS": "-Px"}',
                '{"mvn_profiles": "x"}',
                '{"MAVEN_ARGS": "-f x"}',
                '{"PATH_PREFIX": "x"}',
                '{"SNAPSHOT_METADATA_MAVEN_ARGS": "x"}',
                '{"snapshot_metadata_nexus_password": "x"}',
                '{"SNAPSHOT_METADATA_RETRY_DELAY": "1"}',
                '{"SNAPSHOT_METADATA_CHECK_COORDINATES": "false"}',
                "[]",
                "not json",
                '{"maven_arg\\u017f": "-f x"}',
            ):
                with self.subTest(sbom=sbom, value=value):
                    verdict = self.run_guard(ENV_VARS=value, SBOM_ENABLED=sbom)
                    self.assert_fails(
                        verdict, f"merge guard (sbom {sbom}) rejects {value}"
                    )

    @needs_runner_tools
    def test_sbom_names_matter_only_when_it_runs(self) -> None:
        """The SBOM step's own names fail only with the SBOM on."""
        for value in ('{"JAVA_VERSION": "8"}', '{"syft_cmd": "x"}'):
            with self.subTest(value=value):
                verdict = self.run_guard(ENV_VARS=value, SBOM_ENABLED="true")
                self.assert_fails(
                    verdict, f"merge guard (sbom true) rejects {value}"
                )
                verdict = self.run_guard(ENV_VARS=value, SBOM_ENABLED="false")
                self.assert_passes(
                    verdict, f"merge guard (sbom false) accepts {value}"
                )


@needs_runner_tools
class SbomBudget(GuardCase):
    """Merge lane: SBOM budget.

    The SBOM runs after the deploy with continue-on-error, which cannot
    absorb the job's own timeout, so its budget must leave the job time
    to finish and reach the publish. Offsets sit mid-minute, so the
    round-up of elapsed time cannot cross a boundary during the run.
    """

    workflow = MERGE
    step = BUDGET

    def budget(
        self, label: str, ago: int, job: str, step: str, want: str
    ) -> str:
        """Run the budget ``ago`` seconds into the job and check its minutes.

        Returns the step summary the run wrote.
        """
        with tempfile.TemporaryDirectory() as scratch:
            summary = Path(scratch) / "summary"
            summary.touch()
            verdict = self.run_guard(
                STARTED=str(int(time.time()) - ago),
                JOB_LIMIT=job,
                STEP_LIMIT=step,
                MARGIN="5",
                GITHUB_STEP_SUMMARY=str(summary),
            )
            self.assert_passes(verdict, f"SBOM budget: {label}")
            self.assertEqual(verdict.value("minutes"), want, label)
            return summary.read_text(encoding="utf-8")

    def test_full_limit_at_the_start(self) -> None:
        """At the start, the step gets its whole limit."""
        self.budget("full limit at the start", 20, "45", "30", "30")

    def test_clamped_part_way_in(self) -> None:
        """Fifteen minutes in, the step is clamped to what remains."""
        self.budget("clamped 15 minutes in", 890, "45", "30", "25")

    def test_decimal_limits(self) -> None:
        """Decimal limits are read as the integers they are."""
        self.budget("decimal limits", 890, "45.0", "30.0", "25")

    def test_skipped_when_none_remains(self) -> None:
        """With no time left the budget is zero and the summary says so."""
        summary = self.budget(
            "skipped when none remains", 2370, "45", "30", "0"
        )
        self.assertIn(
            "SBOM skipped", summary, "SBOM budget: a skip left no step summary"
        )

    def test_skipped_past_the_limit(self) -> None:
        """Past the job limit the budget stays zero."""
        self.budget("skipped past the limit", 3000, "45", "30", "0")


class SbomBudgetWiring(ContractCase):
    """Merge lane: the SBOM step takes its timeout from the budget.

    The budget does nothing unless the SBOM step takes its timeout from
    it, and is skipped when it is zero: a step falling back to
    sbom_timeout_minutes would bring the timed-out publish back.
    """

    def check_sbom_timeout(self, merge: Workflow) -> None:
        """Fail unless 'Generate SBOM' reads its timeout from the budget."""
        step = step_of(job_of(merge, "build"), SBOM_STEP)
        self.assertEqual(
            text(step.get("timeout-minutes")),
            "${{ fromJSON(steps.sbom-budget.outputs.minutes) }}",
            f"{MERGE}: '{SBOM_STEP}' does not take its timeout from the"
            " budget",
        )

    def check_sbom_skipped_at_zero(self, merge: Workflow) -> None:
        """Fail unless 'Generate SBOM' is skipped when the budget is zero."""
        step = step_of(job_of(merge, "build"), SBOM_STEP)
        self.assertIn(
            "steps.sbom-budget.outputs.minutes != '0'",
            text(step.get("if")),
            f"{MERGE}: '{SBOM_STEP}' runs when the budget is zero",
        )

    def check_upload_fits_the_margin(self, merge: Workflow) -> None:
        """Fail unless the SBOM upload's fixed timeout sits below the margin.

        Every step after the SBOM must fit the budget's margin, or one
        hanging there reaches the job timeout instead. The SBOM upload
        is the only one that can take long, so bound it below the margin.
        """
        build = job_of(merge, "build")
        timeout = text(step_of(build, SBOM_UPLOAD).get("timeout-minutes"))
        margin = text(env_of(step_of(build, BUDGET)).get("MARGIN"))
        self.assertTrue(
            timeout.isdigit(),
            f"{MERGE}: '{SBOM_UPLOAD}' has no fixed timeout-minutes",
        )
        self.assertLess(
            int(timeout),
            int(margin or "0"),
            f"{MERGE}: '{SBOM_UPLOAD}' timeout {timeout} does not fit the"
            f" SBOM budget's margin of {margin or '?'} minutes",
        )

    def test_sbom_timeout_comes_from_the_budget(self) -> None:
        """The SBOM step's timeout is the budget's output."""
        self.check_sbom_timeout(load_workflow(MERGE))

    def test_sbom_is_skipped_at_zero(self) -> None:
        """The SBOM step's condition tests the budget for zero."""
        self.check_sbom_skipped_at_zero(load_workflow(MERGE))

    def test_upload_fits_the_margin(self) -> None:
        """The SBOM upload's timeout is a number below the margin."""
        self.check_upload_fits_the_margin(load_workflow(MERGE))

    def test_a_fixed_sbom_timeout_fails(self) -> None:
        """An SBOM step falling back to the input fails the check."""
        merge = load_workflow(MERGE)
        step_of(job_of(merge, "build"), SBOM_STEP)["timeout-minutes"] = (
            "${{ inputs.sbom_timeout_minutes }}"
        )
        self.assert_check_fails(self.check_sbom_timeout, merge)

    def test_an_unconditional_sbom_fails(self) -> None:
        """An SBOM step running on a zero budget fails the check."""
        merge = load_workflow(MERGE)
        step_of(job_of(merge, "build"), SBOM_STEP)["if"] = (
            "inputs.sbom_enabled"
        )
        self.assert_check_fails(self.check_sbom_skipped_at_zero, merge)

    def test_an_upload_outside_the_margin_fails(self) -> None:
        """An SBOM upload with no timeout, or one at the margin, fails."""
        merge = load_workflow(MERGE)
        upload = step_of(job_of(merge, "build"), SBOM_UPLOAD)
        del upload["timeout-minutes"]
        self.assert_check_fails(self.check_upload_fits_the_margin, merge)
        upload["timeout-minutes"] = 5
        self.assert_check_fails(self.check_upload_fits_the_margin, merge)


@needs_runner_tools
class MergeInputValidation(GuardCase):
    """Merge lane: input validation."""

    workflow = MERGE
    job = "validate"
    step = VALIDATE

    def validate(
        self,
        server: str,
        repository: str = "snapshots",
        username: str = "",
    ) -> Verdict:
        """Validate ``server``, ``repository`` and ``username`` on a branch."""
        return self.run_guard(
            NEXUS_SERVER=server,
            REPOSITORY_NAME=repository,
            NEXUS_USERNAME=username,
            TARGET_REPOSITORY=SELF,
            CALLER_REPOSITORY=SELF,
            GERRIT_BRANCH="",
            BRANCH_INPUT="",
            TRIGGER_REF="refs/heads/main",
        )

    def test_plain_server(self) -> None:
        """A plain server resolves its endpoint and the repository's name."""
        verdict = self.validate("https://nexus.example.org")
        self.assert_passes(verdict, "plain server")
        self.assertEqual(
            verdict.value("nexus_endpoint"), "nexus.example.org:443"
        )
        self.assertEqual(verdict.value("nexus_username"), "example-repo")

    def test_port_path_trailing_slash_and_username(self) -> None:
        """A port with a leading zero, a path and a username resolve."""
        verdict = self.validate(
            "https://nexus.example.org:08443/nexus/", "snapshots", "deployer"
        )
        self.assert_passes(verdict, "port, path, trailing slash and username")
        self.assertEqual(
            verdict.value("nexus_endpoint"), "nexus.example.org:8443"
        )
        self.assertEqual(verdict.value("nexus_username"), "deployer")

    def test_rejects_malformed_servers(self) -> None:
        """Empty, HTTP, bad ports, double slashes, userinfo, queries fail."""
        for server in (
            "",
            "http://nexus.example.org",
            "https://nexus.example.org:0",
            "https://nexus.example.org:65536",
            "https://nexus.example.org//nexus",
            "https://nexus.example.org/nexus//",
            "https://user@nexus.example.org",
            "https://nexus.example.org?x=1",
            "https://nexus.example.org\n::warning::injected",
        ):
            with self.subTest(server=server):
                verdict = self.validate(server)
                self.assert_fails(verdict, f"server '{server}' rejected")

    def test_rejects_a_repository_name_with_a_slash(self) -> None:
        """A repository name holding a slash fails."""
        verdict = self.validate("https://nexus.example.org", "snap/shots")
        self.assert_fails(verdict, "repository name with a slash")

    def test_rejects_a_username_with_a_space(self) -> None:
        """A username holding a space fails."""
        verdict = self.validate(
            "https://nexus.example.org", "snapshots", "de ployer"
        )
        self.assert_fails(verdict, "username with a space")


@needs_runner_tools
class MergeCheckoutBranch(GuardCase):
    """Merge lane: the branch the checkouts build."""

    workflow = MERGE
    job = "validate"
    step = VALIDATE

    def resolve(
        self, gerrit_branch: str, ref: str, trigger: str, target: str
    ) -> Verdict:
        """Resolve the branch for the given inputs and triggering ref."""
        return self.run_guard(
            NEXUS_SERVER="https://nexus.example.org",
            REPOSITORY_NAME="snapshots",
            NEXUS_USERNAME="",
            GERRIT_BRANCH=gerrit_branch,
            BRANCH_INPUT=ref,
            TRIGGER_REF=trigger,
            TARGET_REPOSITORY=target,
            CALLER_REPOSITORY=SELF,
        )

    def resolves_to(
        self,
        label: str,
        gerrit_branch: str,
        ref: str,
        trigger: str,
        target: str,
        want: str,
    ) -> None:
        """Expect a pass whose checkout_ref is ``want``."""
        verdict = self.resolve(gerrit_branch, ref, trigger, target)
        self.assert_passes(verdict, label)
        self.assertEqual(verdict.value("checkout_ref"), want, label)

    def test_triggering_branch(self) -> None:
        """Without inputs, the triggering branch is built."""
        self.resolves_to(
            "triggering branch",
            "",
            "",
            "refs/heads/main",
            SELF,
            "refs/heads/main",
        )

    def test_repository_named_in_another_case(self) -> None:
        """The target repository matches the caller's whatever its case."""
        self.resolves_to(
            "repository named in another case",
            "",
            "",
            "refs/heads/main",
            "Example-Org/Example-Repo",
            "refs/heads/main",
        )

    def test_gerrit_branch_over_the_trigger(self) -> None:
        """gerrit_branch wins over the ref input and the trigger."""
        self.resolves_to(
            "gerrit_branch over the trigger",
            "stable/x",
            "other",
            "refs/tags/v1",
            SELF,
            "refs/heads/stable/x",
        )

    def test_ref_as_a_name(self) -> None:
        """A ref input given as a branch name is built as that branch."""
        self.resolves_to(
            "ref as a name",
            "",
            "stable/x",
            "refs/tags/v1",
            SELF,
            "refs/heads/stable/x",
        )

    def test_ref_as_a_branch_ref(self) -> None:
        """A ref input given as refs/heads/... is built as that branch."""
        self.resolves_to(
            "ref as a branch ref",
            "",
            "refs/heads/main",
            "refs/pull/1/merge",
            SELF,
            "refs/heads/main",
        )

    def test_another_repository_builds_its_default_branch(self) -> None:
        """Another target repository is built at its default branch."""
        self.resolves_to(
            "another repository: its default branch",
            "",
            "",
            "refs/pull/1/merge",
            "example-org/fixture",
            "",
        )

    def test_rejects_triggers_that_are_no_branch(self) -> None:
        """A tag, a pull request or no triggering ref fails without inputs."""
        for trigger in ("refs/tags/v1.0.0", "refs/pull/1/merge", ""):
            with self.subTest(trigger=trigger):
                verdict = self.resolve("", "", trigger, SELF)
                self.assert_fails(
                    verdict, f"triggering ref '{trigger}' rejected"
                )

    def test_rejects_a_gerrit_branch_with_a_space(self) -> None:
        """A gerrit_branch holding a space fails."""
        verdict = self.resolve("stable x", "", "refs/heads/main", SELF)
        self.assert_fails(verdict, "gerrit_branch with a space")

    def test_rejects_refs_that_are_no_branch(self) -> None:
        """A tag, a pull head, a SHA or a malformed name fails as the ref.

        The last case carries a line break, which must not start a
        workflow command.
        """
        cases = (
            "refs/tags/v1.0.0",
            "refs/pull/1/head",
            "0123456789abcdef0123456789abcdef01234567",
            "a..b",
            "a b",
            "main.lock",
            "main\n::warning::injected",
        )
        verdict: Verdict | None = None
        for ref in cases:
            with self.subTest(ref=ref):
                verdict = self.resolve("", ref, "refs/heads/main", SELF)
                self.assert_fails(verdict, f"ref '{ref}' rejected")
        self.assertIsNotNone(verdict)
        assert verdict is not None
        self.assertFalse(
            verdict.warned(),
            "Branch validation let a line break start a workflow command",
        )


def function_of(script: str) -> str:
    """Return the expand_workspace_vars definition in ``script``.

    From its opening line to its closing brace, with leading spaces
    stripped, as the shell's sed range read it.
    """
    lines: list[str] = []
    inside = False
    for line in script.splitlines():
        if not inside and re.fullmatch(
            r" *expand_workspace_vars\(\) \{", line
        ):
            inside = True
        if inside:
            lines.append(line.lstrip(" "))
            if re.fullmatch(r" *\}", line):
                inside = False
    return "\n".join(lines)


class PlaceholderExpansion(GuardCase):
    """Merge lane: placeholder expansion matches maven-build-action.

    maven-build-action expands workspace placeholders in mvn-opts and
    mvn-params; the merge lane repeats the expansion for the fetch and
    the SBOM. Its function must stay the pinned action's: the vendored
    copy is that action's script at the SHA below, and moving the pin
    without refreshing the copy fails here.
    """

    workflow = MERGE
    step = EXPAND

    def check_pin(self, merge_text: str) -> None:
        """Fail unless every maven-build-action use is at the vendored pin."""
        pins = set(
            re.findall(
                r"lfreleng-actions/maven-build-action@[0-9a-f]*", merge_text
            )
        )
        self.assertEqual(
            pins,
            {f"lfreleng-actions/maven-build-action@{EXPAND_PIN}"},
            f"{MERGE}: maven-build-action is not pinned to {EXPAND_PIN};"
            f" refresh {EXPAND_VENDORED} from the new pin and update"
            " EXPAND_PIN",
        )

    def check_function_matches(self, merge: Workflow) -> None:
        """Fail unless the lane's function is the vendored one."""
        vendored = function_of(read_text(EXPAND_VENDORED))
        self.assertTrue(
            vendored, f"{EXPAND_VENDORED}: no expand_workspace_vars"
        )
        self.assertEqual(
            function_of(run_of(merge, "build", EXPAND)),
            vendored,
            f"{MERGE}: '{EXPAND}' differs from {EXPAND_VENDORED}",
        )

    def test_pinned_to_the_vendored_sha(self) -> None:
        """The lane pins maven-build-action at the vendored script's SHA."""
        self.check_pin(read_text(MERGE))

    def test_a_moved_pin_fails(self) -> None:
        """A second pin, or a moved one, fails the check."""
        moved = read_text(MERGE).replace(EXPAND_PIN, "0" * 40, 1)
        self.assert_check_fails(self.check_pin, moved)

    def test_function_matches_the_vendored_copy(self) -> None:
        """The lane's expand_workspace_vars is the vendored one."""
        self.check_function_matches(load_workflow(MERGE))

    def test_a_drifted_function_fails(self) -> None:
        """A lane function with one line changed fails the check."""
        merge = load_workflow(MERGE)
        step = step_of(job_of(merge, "build"), EXPAND)
        step["run"] = step["run"].replace(
            "expand_workspace_vars() {", "expand_workspace_vars() {\n  :", 1
        )
        self.assert_check_fails(self.check_function_matches, merge)

    @needs_runner_tools
    def test_expands_workspace_placeholders_only(self) -> None:
        """GITHUB_WORKSPACE and RUNNER_OS expand; everything else stays."""
        verdict = self.run_guard(
            MVN_OPTS="-Dw=${GITHUB_WORKSPACE}/x -Dos=$RUNNER_OS",
            MVN_PARAMS="-Dh=${HOME} -Db=${project.basedir} $(id) $1\n-Dz",
            GITHUB_WORKSPACE="/ws",
            RUNNER_OS="Linux",
            HOME="/home/x",
        )
        self.assert_passes(verdict, "placeholder expansion")
        self.assertEqual(
            verdict.heredoc("mvn_opts"), "-Dw=/ws/x -Dos=Linux", verdict.output
        )
        self.assertEqual(
            verdict.heredoc("mvn_params"),
            "-Dh=${HOME} -Db=${project.basedir} $(id) $1\n-Dz",
            verdict.output,
        )


@needs_runner_tools
class CleanM2repo(GuardCase):
    """Merge lane: m2repo absent before the fetch."""

    workflow = MERGE
    step = CLEAN

    def test_workspace_without_an_m2repo(self) -> None:
        """A workspace holding no m2repo passes."""
        with tempfile.TemporaryDirectory() as workspace:
            verdict = self.run_guard(GITHUB_WORKSPACE=workspace)
            self.assert_passes(verdict, "workspace without an m2repo")

    def test_workspace_with_an_m2repo(self) -> None:
        """A workspace already holding an m2repo fails."""
        with tempfile.TemporaryDirectory() as workspace:
            (Path(workspace) / "m2repo").mkdir()
            verdict = self.run_guard(GITHUB_WORKSPACE=workspace)
            self.assert_fails(verdict, "workspace with an m2repo")


class StaleM2repo(GuardCase):
    """Merge lane: publish refuses a stale m2repo.

    "Re-run failed jobs" reruns the publish with the build's outputs and
    artefact from an earlier attempt; publishing that m2repo could roll
    Nexus back. The guard compares the attempts, so the build must
    record its own.
    """

    workflow = MERGE
    job = "publish"
    step = STALE

    @needs_runner_tools
    def test_artefact_from_this_attempt(self) -> None:
        """An m2repo built in this attempt passes."""
        verdict = self.run_guard(BUILD_ATTEMPT="2", RUN_ATTEMPT="2")
        self.assert_passes(verdict, "artefact from this attempt")

    @needs_runner_tools
    def test_artefact_from_an_earlier_attempt(self) -> None:
        """An m2repo built in an earlier attempt fails."""
        verdict = self.run_guard(BUILD_ATTEMPT="1", RUN_ATTEMPT="2")
        self.assert_fails(verdict, "artefact from an earlier attempt")

    def check_build_records_its_attempt(self, merge: Workflow) -> None:
        """Fail unless the build job's attempt output is github.run_attempt."""
        attempt = text(outputs_of(job_of(merge, "build")).get("attempt"))
        self.assertEqual(
            attempt,
            "${{ github.run_attempt }}",
            f"{MERGE}: the build job's attempt output is '{attempt}', not"
            " github.run_attempt",
        )

    def check_guard_reads_the_build_attempt(self, merge: Workflow) -> None:
        """Fail unless the guard reads the build job's attempt output."""
        step = step_of(job_of(merge, "publish"), STALE)
        attempt = text(env_of(step).get("BUILD_ATTEMPT"))
        self.assertEqual(
            attempt,
            "${{ needs.build.outputs.attempt }}",
            f"{MERGE}: '{STALE}' reads '{attempt}', not the build job's"
            " attempt output",
        )

    def check_guard_precedes_the_download(self, merge: Workflow) -> None:
        """Fail unless the publish job refuses before it downloads."""
        publish = job_of(merge, "publish")
        self.assertLess(
            step_index(publish, STALE),
            step_index(publish, M2REPO_DOWNLOAD),
            f"{MERGE}: the publish job downloads the m2repo before refusing"
            " a stale one",
        )

    def test_build_records_its_attempt(self) -> None:
        """The build job publishes github.run_attempt."""
        self.check_build_records_its_attempt(load_workflow(MERGE))

    def test_guard_reads_the_build_attempt(self) -> None:
        """The guard's BUILD_ATTEMPT is the build job's output."""
        self.check_guard_reads_the_build_attempt(load_workflow(MERGE))

    def test_guard_precedes_the_download(self) -> None:
        """The guard runs before the m2repo download."""
        self.check_guard_precedes_the_download(load_workflow(MERGE))

    def test_an_unrecorded_attempt_fails(self) -> None:
        """A build job without the attempt output fails the check."""
        merge = load_workflow(MERGE)
        del job_of(merge, "build")["outputs"]["attempt"]
        self.assert_check_fails(self.check_build_records_its_attempt, merge)

    def test_a_guard_reading_elsewhere_fails(self) -> None:
        """A guard reading the run attempt as the build's fails the check."""
        merge = load_workflow(MERGE)
        step_of(job_of(merge, "publish"), STALE)["env"]["BUILD_ATTEMPT"] = (
            "${{ github.run_attempt }}"
        )
        self.assert_check_fails(
            self.check_guard_reads_the_build_attempt, merge
        )

    def test_a_guard_after_the_download_fails(self) -> None:
        """A guard moved behind the download fails the check."""
        merge = load_workflow(MERGE)
        steps = steps_of(job_of(merge, "publish"))
        guard = steps.pop(step_index(job_of(merge, "publish"), STALE))
        steps.insert(
            step_index(job_of(merge, "publish"), M2REPO_DOWNLOAD) + 1, guard
        )
        self.assert_check_fails(self.check_guard_precedes_the_download, merge)


@needs_runner_tools
class DeployLanded(GuardCase):
    """Merge lane: the deploy landed in the m2repo."""

    workflow = MERGE
    step = LANDED

    def setUp(self) -> None:
        """Give each test a scratch directory for its m2repo trees."""
        super().setUp()
        self.scratch = Path(tempfile.mkdtemp())
        self.addCleanup(self.remove_scratch)

    def remove_scratch(self) -> None:
        """Remove the scratch directory, links and all."""
        for path in sorted(self.scratch.rglob("*"), reverse=True):
            if path.is_symlink() or path.is_file():
                path.unlink()
            else:
                path.rmdir()
        self.scratch.rmdir()

    def m2repo(self, name: str, *files: str) -> Path:
        """Build m2repo ``name`` holding the relative paths ``files``."""
        root = self.scratch / name
        root.mkdir(parents=True, exist_ok=True)
        for file in files:
            (root / file).parent.mkdir(parents=True, exist_ok=True)
            (root / file).touch()
        return root

    def landed(self, path: Path, groups: str = "org/example") -> Verdict:
        """Run the check over ``path`` with ``groups`` as the group paths."""
        return self.run_guard(M2REPO_PATH=str(path), GROUP_PATHS=groups)

    def test_deployed_tree(self) -> None:
        """A SNAPSHOT with its checksum and metadata passes, counting files."""
        valid = self.m2repo(
            "valid",
            SNAPSHOT_JAR,
            f"{SNAPSHOT_JAR}.sha1",
            f"{VERSION}/maven-metadata.xml",
            "org/example/core/maven-metadata.xml",
        )
        verdict = self.landed(valid)
        self.assert_passes(verdict, "deployed tree")
        self.assertEqual(verdict.value("file_count"), "4")
        verdict = self.landed(valid, "com/other org/example")
        self.assert_passes(verdict, "deployed tree, second group path")

    def test_metadata_and_checksums_only(self) -> None:
        """A tree holding only metadata and its checksums fails."""
        tree = self.m2repo(
            "metadata-only",
            f"{VERSION}/maven-metadata.xml",
            f"{VERSION}/maven-metadata.xml.sha1",
        )
        self.assert_fails(self.landed(tree), "metadata and checksums only")

    def test_a_file_outside_the_group_paths(self) -> None:
        """A file under a group fetch did not read fails."""
        tree = self.m2repo(
            "outside",
            SNAPSHOT_JAR,
            "org/examples/core/1.0.0-SNAPSHOT/core-1.0.0-20260101.000000-1.jar",
        )
        self.assert_fails(self.landed(tree), "a file outside the group paths")

    def test_a_release_artefact_beside_a_snapshot(self) -> None:
        """A release version directory beside a SNAPSHOT fails."""
        tree = self.m2repo(
            "release",
            SNAPSHOT_JAR,
            "org/example/api/1.0.0/api-1.0.0.jar",
            "org/example/api/maven-metadata.xml",
        )
        self.assert_fails(
            self.landed(tree), "a release artefact beside a SNAPSHOT"
        )

    def test_no_group_paths(self) -> None:
        """A valid tree with no group paths fails."""
        valid = self.m2repo("valid", SNAPSHOT_JAR)
        self.assert_fails(self.landed(valid, ""), "no group paths")

    def test_no_m2repo(self) -> None:
        """An absent m2repo fails."""
        self.assert_fails(self.landed(self.scratch / "absent"), "no m2repo")

    def test_a_release_file_disguised_as_metadata(self) -> None:
        """A release file named like metadata or a checksum fails.

        Beside a valid SNAPSHOT: a check that exempts by name pattern
        skips it, and the publish would push a release to the snapshot
        repository. Only the exact metadata names, at the artifact
        level, are exempt.
        """
        for disguise in (
            "maven-metadata.xml-1.0.0.jar",
            "maven-metadata.xmlx",
            "api-1.0.0.jar.sha1",
            "api-1.0.0.md5",
            "maven-metadata.xml.sha1.jar",
        ):
            with self.subTest(disguise=disguise):
                tree = self.m2repo(
                    f"disguised-{disguise}",
                    SNAPSHOT_JAR,
                    f"org/example/api/1.0.0/{disguise}",
                )
                self.assert_fails(
                    self.landed(tree),
                    f"a release file disguised as {disguise}",
                )

    def test_version_level_metadata_under_a_release_version(self) -> None:
        """Metadata names are exempt only directly under an artifact directory.

        Inside a release version directory they are release content too.
        """
        tree = self.m2repo(
            "release-metadata",
            SNAPSHOT_JAR,
            "org/example/api/1.0.0/maven-metadata.xml",
        )
        self.assert_fails(
            self.landed(tree), "version-level metadata under a release version"
        )

    def test_an_artifact_level_file_disguised_as_metadata(self) -> None:
        """At the artifact level only the exact name decides.

        Beside a real SNAPSHOT version directory the position passes: a
        file merely named like metadata or a checksum there is not
        metadata.
        """
        for disguise in (
            "maven-metadata.xml-1.0.0.jar",
            "core-1.0.0.jar.sha1",
        ):
            with self.subTest(disguise=disguise):
                tree = self.m2repo(
                    f"artifact-disguised-{disguise}",
                    SNAPSHOT_JAR,
                    f"org/example/core/{disguise}",
                )
                self.assert_fails(
                    self.landed(tree),
                    f"an artifact-level file disguised as {disguise}",
                )

    def test_artifact_level_metadata_and_its_checksums(self) -> None:
        """Every exact metadata name stays exempt at the artifact level."""
        tree = self.m2repo(
            "artifact-metadata",
            SNAPSHOT_JAR,
            "org/example/core/maven-metadata.xml",
            "org/example/core/maven-metadata.xml.md5",
            "org/example/core/maven-metadata.xml.sha1",
            "org/example/core/maven-metadata.xml.sha256",
            "org/example/core/maven-metadata.xml.sha512",
        )
        self.assert_passes(
            self.landed(tree), "artifact-level metadata and its checksums"
        )

    def test_artifact_level_metadata_beside_a_dot_prefixed_snapshot(
        self,
    ) -> None:
        """A version beginning with a dot still makes its metadata count.

        The hand-off uploads hidden files, and a shell glob skips
        dot-prefixed names unless asked for them.
        """
        tree = self.m2repo(
            "hidden-version",
            "org/example/core/.1-SNAPSHOT/core-.1-20260101.000000-1.jar",
            "org/example/core/maven-metadata.xml",
        )
        self.assert_passes(
            self.landed(tree),
            "artifact-level metadata beside a dot-prefixed SNAPSHOT",
        )

    def test_group_level_plugin_index(self) -> None:
        """A maven-plugin deploy's group-level index counts as metadata.

        It sits at <groupPath>/maven-metadata.xml, beside artifact
        directories rather than version directories, including for a
        new plugin whose index Nexus has never published, so fetch
        seeded none.
        """
        tree = self.m2repo(
            "plugin-index",
            "org/example/core-maven-plugin/1.0.0-SNAPSHOT/"
            "core-maven-plugin-1.0.0-20260101.000000-1.jar",
            "org/example/core-maven-plugin/maven-metadata.xml",
            "org/example/maven-metadata.xml",
            "org/example/maven-metadata.xml.sha1",
        )
        self.assert_passes(self.landed(tree), "group-level plugin index")

    def test_group_level_metadata_beside_release_artifacts_alone(self) -> None:
        """The same file beside only release artifacts is not a SNAPSHOT's."""
        tree = self.m2repo(
            "release-plugin-index",
            SNAPSHOT_JAR,
            "org/other/api/1.0.0/api-1.0.0.jar",
            "org/other/maven-metadata.xml",
        )
        self.assert_fails(
            self.landed(tree, "org/example org/other"),
            "group-level metadata beside release artifacts alone",
        )

    def test_release_metadata_beside_a_sibling_snapshot(self) -> None:
        """Metadata inside a release version directory stays a release.

        Even when a sibling artifact has a SNAPSHOT: the check looks
        down from the file's directory, never up or across. A glob's
        middle .* matches .. on bash before 5.2, which would have
        reached that sibling.
        """
        tree = self.m2repo(
            "release-beside-snapshot",
            SNAPSHOT_JAR,
            "org/example/api/1.0.0/maven-metadata.xml",
        )
        (tree / "org/example/api/2.0-SNAPSHOT").mkdir(parents=True)
        self.assert_fails(
            self.landed(tree), "release metadata beside a sibling SNAPSHOT"
        )

    def test_metadata_above_the_group_level(self) -> None:
        """Two levels down is the deepest metadata belongs.

        A file further up, over a parent group, is nothing a deploy
        writes.
        """
        tree = self.m2repo(
            "above-group", SNAPSHOT_JAR, "org/maven-metadata.xml"
        )
        self.assert_fails(
            self.landed(tree, "org"), "metadata above the group level"
        )

    def test_an_artifact_id_beginning_with_maven_metadata(self) -> None:
        """An artifactId beginning with maven-metadata.xml is an artifact.

        Inside a SNAPSHOT version only the exact metadata names and
        checksum files are bookkeeping, so its POM must count as
        deployed.
        """
        odd = "org/example/maven-metadata.xml/1.0.0-SNAPSHOT"
        tree = self.m2repo(
            "prefixed-artifact",
            f"{odd}/maven-metadata.xml-1.0.0-20260101.000000-1.pom",
            f"{odd}/maven-metadata.xml-1.0.0-20260101.000000-1.pom.sha1",
            f"{odd}/maven-metadata.xml",
        )
        self.assert_passes(
            self.landed(tree),
            "an artifactId beginning with maven-metadata.xml",
        )

    def test_a_symbolic_link_to_a_directory(self) -> None:
        """A link to a release directory outside the tree fails.

        Beside a valid SNAPSHOT: find -type f skips it, but the upload
        would follow it.
        """
        tree = self.m2repo(
            "linked", SNAPSHOT_JAR, "org/example/api/maven-metadata.xml"
        )
        release = self.m2repo("release-dir", "api-1.0.jar")
        (tree / "org/example/api/1.0").symlink_to(release)
        self.assert_fails(self.landed(tree), "a symbolic link to a directory")

    def test_a_symbolic_link_to_a_file(self) -> None:
        """A link to a file inside the SNAPSHOT fails."""
        tree = self.m2repo("file-link", SNAPSHOT_JAR)
        (tree / VERSION / "core-1.0.0-20260101.000000-2.jar").symlink_to(
            "core-1.0.0-20260101.000000-1.jar"
        )
        self.assert_fails(self.landed(tree), "a symbolic link to a file")

    def test_an_m2repo_that_is_itself_a_link(self) -> None:
        """An m2repo path that is a link to a valid tree fails."""
        self.m2repo(
            "valid", SNAPSHOT_JAR, "org/example/core/maven-metadata.xml"
        )
        link = self.scratch / "root-link"
        link.symlink_to("valid")
        self.assert_fails(self.landed(link), "an m2repo that is itself a link")


def metadata_prunes(job: dict[str, object], checked: bool) -> int:
    """Count the prune steps of ``job``, with the coordinate check when asked.

    A prune step keeps its name and mode under any ``uses:`` when
    ``checked`` is false; with it true, the step must also run the
    metadata action with check_coordinates on.
    """
    count = 0
    for step in steps_of(job):
        inputs = with_of(step)
        if inputs.get("mode") != "prune":
            continue
        if checked and not (
            is_action(step, METADATA_ACTION)
            and inputs.get("check_coordinates") == "true"
        ):
            continue
        count += 1
    return count


def metadata_pins(job: dict[str, object]) -> set[str]:
    """Return the refs at which ``job`` runs the metadata action."""
    return {
        uses_of(step)
        for step in steps_of(job)
        if is_action(step, METADATA_ACTION)
    }


class CoordinateCheck(ContractCase):
    """Merge lane: coordinate check.

    prune refuses a SNAPSHOT coordinate fetch did not read, which the
    landed check's group paths cannot see inside a known group. A job
    calling the lane cannot set continue-on-error, so testing.yaml's
    merge-prune-check proves the rejection by running the lane's
    metadata action itself. That proves the lane only while the check
    stays on in both and every use shares one pin.
    """

    def check_lane_prunes_with_the_check(self, merge: Workflow) -> None:
        """Fail unless the lane's prune runs the action with the check on.

        Each prune must still run the metadata action: a step keeping
        its name and inputs under another 'uses:' would pass on inputs
        alone, while the fetch kept the pin comparison satisfied.
        """
        count = sum(
            1
            for step in steps_of(job_of(merge, "build"))
            if step.get("name") == PRUNE
            and is_action(step, METADATA_ACTION)
            and with_of(step).get("mode") == "prune"
            and with_of(step).get("check_coordinates") == "true"
        )
        self.assertEqual(
            count,
            1,
            f"{MERGE}: '{PRUNE}' must run maven-snapshot-metadata-action in"
            " prune mode with check_coordinates: 'true'",
        )

    def check_testing_prunes_twice(self, testing: Workflow) -> None:
        """Fail unless merge-prune-check prunes twice with the check on.

        Exactly two prunes, the rejection and the passing baseline, both
        running the action with the check on: counting only
        misconfigured ones would pass when the prunes are gone
        altogether.
        """
        job = job_of(testing, "merge-prune-check")
        prunes = metadata_prunes(job, checked=False)
        checked = metadata_prunes(job, checked=True)
        self.assertEqual(
            (prunes, checked),
            (2, 2),
            f"{TESTING}: merge-prune-check must prune twice with"
            " maven-snapshot-metadata-action and check_coordinates: 'true',"
            f" as the lane does; found {checked} of {prunes}",
        )

    def check_one_pin(self, merge: Workflow, testing: Workflow) -> None:
        """Fail unless the lane and merge-prune-check share one pin."""
        lane_pins = metadata_pins(job_of(merge, "build"))
        test_pins = metadata_pins(job_of(testing, "merge-prune-check"))
        self.assertTrue(
            lane_pins and test_pins and len(lane_pins | test_pins) == 1,
            "maven-snapshot-metadata-action must have one pin across"
            f" {MERGE} and {TESTING}'s merge-prune-check:"
            f" {', '.join(sorted(lane_pins))} /"
            f" {', '.join(sorted(test_pins))}",
        )

    def test_lane_prunes_with_the_check(self) -> None:
        """The lane's prune runs the action with check_coordinates on."""
        self.check_lane_prunes_with_the_check(load_workflow(MERGE))

    def test_testing_prunes_twice(self) -> None:
        """merge-prune-check prunes twice with the check on."""
        self.check_testing_prunes_twice(load_workflow(TESTING))

    def test_one_pin(self) -> None:
        """The lane and merge-prune-check pin the action alike."""
        self.check_one_pin(load_workflow(MERGE), load_workflow(TESTING))

    def test_a_prune_without_the_check_fails(self) -> None:
        """A lane prune with the check off, or under another action, fails."""
        merge = load_workflow(MERGE)
        prune = step_of(job_of(merge, "build"), PRUNE)
        prune["with"]["check_coordinates"] = "false"
        self.assert_check_fails(self.check_lane_prunes_with_the_check, merge)
        prune["with"]["check_coordinates"] = "true"
        prune["uses"] = "example/other-action@" + "0" * 40
        self.assert_check_fails(self.check_lane_prunes_with_the_check, merge)

    def test_a_missing_testing_prune_fails(self) -> None:
        """merge-prune-check with one prune, or one unchecked, fails."""
        testing = load_workflow(TESTING)
        steps = steps_of(job_of(testing, "merge-prune-check"))
        prunes = [s for s in steps if with_of(s).get("mode") == "prune"]
        prunes[0]["with"]["check_coordinates"] = "false"
        self.assert_check_fails(self.check_testing_prunes_twice, testing)
        steps.remove(prunes[0])
        self.assert_check_fails(self.check_testing_prunes_twice, testing)

    def test_a_second_pin_fails(self) -> None:
        """merge-prune-check at another pin fails the check."""
        testing = load_workflow(TESTING)
        for step in steps_of(job_of(testing, "merge-prune-check")):
            if is_action(step, METADATA_ACTION):
                step["uses"] = f"{METADATA_ACTION}@" + "0" * 40
                break
        self.assert_check_fails(
            self.check_one_pin, load_workflow(MERGE), testing
        )


class SubmoduleWiring(ContractCase):
    """Checkouts: submodule wiring."""

    def checkouts_of(
        self, workflow: Workflow
    ) -> list[tuple[str, dict[str, object]]]:
        """Return each checkout step of ``workflow`` with its job ID."""
        return [
            (job_id, step)
            for job_id, job in jobs_of(workflow).items()
            for step in steps_of(job)
            if is_action(step, *CHECKOUT_ACTIONS)
        ]

    def check_checkouts_wired(self, path: str, workflow: Workflow) -> None:
        """Fail unless every checkout passes checkout_submodules through."""
        checkouts = self.checkouts_of(workflow)
        self.assertTrue(checkouts, f"{path}: found no checkout steps")
        unwired = [
            f"{job_id}: {step.get('name')}"
            for job_id, step in checkouts
            if with_of(step).get("submodules") != WIRING
        ]
        self.assertEqual(
            unwired,
            [],
            f"{path}: checkouts without submodule wiring:"
            f" {', '.join(unwired)}",
        )

    def check_gerrit_checkouts_followed(
        self, path: str, workflow: Workflow
    ) -> None:
        """Fail unless the initialisation step follows every Gerrit checkout.

        The merge lane builds the branch head and has no Gerrit checkout.
        """
        for job in jobs_of(workflow).values():
            steps = steps_of(job)
            for index, step in enumerate(steps):
                if not is_action(step, GERRIT_CHECKOUT):
                    continue
                follower = (
                    text(steps[index + 1].get("name"))
                    if index + 1 < len(steps)
                    else "none"
                )
                self.assertEqual(
                    follower,
                    INIT_STEP,
                    f"{path}: a Gerrit checkout is followed by '{follower}'",
                )

    def check_one_init_variant(self, *workflows: Workflow) -> None:
        """Fail unless every initialisation step shares one if: and run:."""
        variants = {
            text(step.get("if")) + "\n" + text(step.get("run"))
            for workflow in workflows
            for job in jobs_of(workflow).values()
            for step in steps_of(job)
            if step.get("name") == INIT_STEP
        }
        self.assertEqual(
            len(variants),
            1,
            f"the '{INIT_STEP}' steps differ between jobs or lanes",
        )

    def test_every_checkout_is_wired(self) -> None:
        """Each lane's checkouts all pass checkout_submodules through."""
        for path in LANES:
            with self.subTest(workflow=path):
                self.check_checkouts_wired(path, load_workflow(path))

    def test_gerrit_checkouts_are_followed_by_the_initialisation(self) -> None:
        """Each Gerrit checkout is followed by the initialisation step."""
        for path in LANES:
            with self.subTest(workflow=path):
                self.check_gerrit_checkouts_followed(path, load_workflow(path))

    def test_one_initialisation_variant(self) -> None:
        """The initialisation step is the same in every job of both lanes."""
        self.check_one_init_variant(
            load_workflow(MAVEN), load_workflow(GRADLE)
        )

    def test_an_unwired_checkout_fails(self) -> None:
        """A checkout without the submodules input fails the check."""
        maven = load_workflow(MAVEN)
        del step_of(job_of(maven, "build"), "Checkout repository")["with"][
            "submodules"
        ]
        self.assert_check_fails(self.check_checkouts_wired, MAVEN, maven)

    def test_a_gerrit_checkout_without_its_follower_fails(self) -> None:
        """A Gerrit checkout followed by another step fails the check."""
        maven = load_workflow(MAVEN)
        steps = steps_of(job_of(maven, "build"))
        steps.pop(step_index(job_of(maven, "build"), INIT_STEP))
        self.assert_check_fails(
            self.check_gerrit_checkouts_followed, MAVEN, maven
        )

    def test_a_drifted_initialisation_fails(self) -> None:
        """An initialisation step with another condition fails the check."""
        gradle = load_workflow(GRADLE)
        step_of(job_of(gradle, "build"), INIT_STEP)["if"] = (
            "inputs.gerrit_refspec != ''"
        )
        self.assert_check_fails(
            self.check_one_init_variant, load_workflow(MAVEN), gradle
        )


@needs_runner_tools
class GerritSubmoduleInitialisation(GuardCase):
    """Gerrit checkout: submodules a change adds."""

    step = INIT_STEP

    def test_initialises_a_submodule_the_change_adds(self) -> None:
        """The step fills a submodule the change adds and the base lacks.

        What checkout-gerrit-change-action v1.1.0 does: actions/checkout
        v7.0.1 checks out the base, then runs 'submodule sync' and
        'submodule update --init --force', registering the submodules
        the base has. The action then fetches the change, switches to
        it, and runs a plain update, which leaves a newly added one
        inactive.
        """
        with tempfile.TemporaryDirectory() as scratch:
            tmp = Path(scratch)
            # Local repositories, isolated from the caller's own git
            # settings (submodule.recurse, for one, changes what a switch
            # does): an identity, no signing, and file transport for the
            # submodule, which git refuses by default.
            env = {
                **os.environ,
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_COUNT": "5",
                "GIT_CONFIG_KEY_0": "user.name",
                "GIT_CONFIG_VALUE_0": "Wiring Check",
                "GIT_CONFIG_KEY_1": "user.email",
                "GIT_CONFIG_VALUE_1": "wiring@example.org",
                "GIT_CONFIG_KEY_2": "commit.gpgsign",
                "GIT_CONFIG_VALUE_2": "false",
                "GIT_CONFIG_KEY_3": "protocol.file.allow",
                "GIT_CONFIG_VALUE_3": "always",
                "GIT_CONFIG_KEY_4": "init.defaultBranch",
                "GIT_CONFIG_VALUE_4": "main",
            }

            def git(*args: str, cwd: Path | None = None) -> None:
                subprocess.run(
                    ["git", *args],
                    check=True,
                    cwd=cwd,
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

            module = tmp / "module"
            git("init", "-q", str(module))
            (module / "README").write_text(
                "module content\n", encoding="utf-8"
            )
            git("add", "README", cwd=module)
            git("commit", "-q", "-m", "Module", cwd=module)
            project = tmp / "project"
            git("init", "-q", str(project))
            (project / "README").write_text("base\n", encoding="utf-8")
            git("add", "README", cwd=project)
            git("commit", "-q", "-m", "Base", cwd=project)
            git("switch", "-q", "-c", "change", cwd=project)
            git(
                "submodule",
                "--quiet",
                "add",
                str(module),
                "module",
                cwd=project,
            )
            git("commit", "-q", "-m", "Add a submodule", cwd=project)
            git("switch", "-q", "main", cwd=project)
            checkout = tmp / "checkout"
            git("clone", "-q", str(project), str(checkout))
            git("submodule", "sync", cwd=checkout)
            git("submodule", "update", "--init", "--force", cwd=checkout)
            git("fetch", "-q", "origin", "change", cwd=checkout)
            git("checkout", "-q", "FETCH_HEAD", cwd=checkout)
            git("submodule", "update", cwd=checkout)
            self.assertFalse(
                (checkout / "module" / "README").exists(),
                "the plain update initialised the new submodule, so this case"
                " no longer tests anything",
            )
            verdict = run_script(self.script, env, cwd=checkout)
            self.assert_passes(verdict, "the initialisation step")
            self.assertTrue(
                (checkout / "module" / "README").exists(),
                "the initialisation step left a new submodule empty",
            )


class ArtefactSuffixes(ContractCase):
    """Lanes: artefact names carry artifact_suffix.

    A matrix calls a lane once per cell in one run, and download-artifact
    resolves a name to the newest upload, so every artefact name a lane
    chooses, for an upload or a download, must end with the call's
    suffix. A name without it would hand one cell another cell's SBOM
    or, in the merge lane, another cell's m2repo to publish. The guard
    covers each step that names an artefact: upload-artifact,
    download-artifact, and the actions the lanes pass a name to.
    repository-metadata-action takes no name; it suffixes its upload
    with a timestamp and a random part of its own, so it cannot collide.
    A grype-scan-action step in validate-only mode checks its inputs
    and uploads nothing, so it names no artefact either. No other
    action here reads that input, so on any other step the key is a
    stray one the action ignores, and the step is held to the suffix
    like the rest.

    A download by artifact-ids resolves no name at all: it fetches the
    one upload whose ID it was given, and download-artifact rejects a
    name beside it. Such a step passes when the ID is an output of a job
    in the same workflow that carries an upload-artifact step's
    artifact-id, since that upload's name the loop checks in its turn;
    an ID from anywhere else, or a name beside the ID, fails.
    """

    def check_artefact_names(self, path: str, workflow: Workflow) -> None:
        """Fail unless every artefact name carries the suffix or goes by ID."""
        count = 0
        for step in (
            s for job in jobs_of(workflow).values() for s in steps_of(job)
        ):
            if not is_action(step, *ARTEFACT_ACTIONS):
                continue
            inputs = with_of(step)
            if inputs.get("artifact-upload") == "false":
                continue
            if is_action(step, GRYPE_ACTION) and (
                inputs.get("validate-only") == "true"
            ):
                continue
            count += 1
            label = text(step.get("name"))
            name = text(present(inputs, "name", "artifact-name"))
            ids = text(inputs.get("artifact-ids"))
            if ids:
                self.check_download_by_id(path, workflow, label, name, ids)
                continue
            self.assertTrue(
                name.endswith(SUFFIX),
                f"{path}: '{label}' names '{name or 'its default'}' without"
                " the artifact_suffix",
            )
        self.assertGreater(
            count, 0, f"{path}: found no artefact names to check"
        )

    def check_download_by_id(
        self, path: str, workflow: Workflow, label: str, name: str, ids: str
    ) -> None:
        """Fail unless ``ids`` is the artifact-id of an upload in the lane."""
        self.assertEqual(
            name,
            "",
            f"{path}: '{label}' names '{name}' beside artifact-ids, which"
            " download-artifact rejects",
        )
        match = re.fullmatch(
            re.escape(NEEDS_PREFIX)
            + r"(.+?)\.outputs\.(.+)"
            + re.escape(CLOSE),
            ids,
        )
        self.assertIsNotNone(
            match,
            f"{path}: '{label}' downloads by '{ids}', not by the output of a"
            " job in this workflow",
        )
        assert match is not None
        job_id, output = match.group(1), match.group(2)
        upload = text(
            outputs_of(jobs_of(workflow).get(job_id, {})).get(output)
        )
        id_match = re.fullmatch(
            re.escape(STEPS_PREFIX)
            + r"(.+?)\.outputs\.artifact-id"
            + re.escape(CLOSE),
            upload,
        )
        self.assertIsNotNone(
            id_match,
            f"{path}: '{label}' downloads by {job_id}'s {output}, which is"
            f" '{upload or 'unset'}', not an upload's artifact-id",
        )
        assert id_match is not None
        upload_id = id_match.group(1)
        upload_step = step_with_id(
            jobs_of(workflow).get(job_id, {}), upload_id
        )
        uses = "" if upload_step is None else uses_of(upload_step)
        self.assertTrue(
            uses.startswith("actions/upload-artifact@"),
            f"{path}: '{label}' downloads by the artifact-id of step"
            f" '{upload_id}' in {job_id}, which runs '{uses or 'no action'}',"
            " not upload-artifact",
        )

    def test_every_artefact_name_carries_the_suffix(self) -> None:
        """Each lane's artefact names end with the suffix or go by an ID."""
        for path in LANES:
            with self.subTest(workflow=path):
                self.check_artefact_names(path, load_workflow(path))

    def test_a_name_without_the_suffix_fails(self) -> None:
        """An upload named without the suffix fails the check."""
        maven = load_workflow(MAVEN)
        step_of(job_of(maven, "build"), SBOM_UPLOAD)["with"]["name"] = (
            "sbom-files"
        )
        self.assert_check_fails(self.check_artefact_names, MAVEN, maven)

    def test_a_scan_marked_validate_only_as_yaml_true_fails(self) -> None:
        """A grype step with validate-only as YAML true, unnamed, fails.

        The action reads the string 'true'; the skip reads the same, so
        a bare boolean does not pass a real scan over unexamined.
        """
        gradle = load_workflow(GRADLE)
        steps_of(job_of(gradle, "grype")).append(
            {
                "name": "Validate again",
                "uses": f"{GRYPE_ACTION}@{'0' * 40}",
                "with": {"validate-only": True},
            }
        )
        self.assert_check_fails(self.check_artefact_names, GRADLE, gradle)

    def test_an_upload_marked_validate_only_fails(self) -> None:
        """An unsuffixed upload with a stray validate-only key fails.

        upload-artifact has no such input, so the step uploads all the
        same; only grype-scan-action's validate-only mode names no
        artefact, and only that action earns the skip.
        """
        maven = load_workflow(MAVEN)
        inputs = step_of(job_of(maven, "build"), SBOM_UPLOAD)["with"]
        inputs["name"] = "sbom-files"
        inputs["validate-only"] = "true"
        self.assert_check_fails(self.check_artefact_names, MAVEN, maven)

    def test_an_empty_name_beside_a_suffixed_artifact_name_fails(self) -> None:
        """An upload with name: '' and a suffixed artifact-name fails.

        upload-artifact reads name, so the empty string is the name it
        would use, and the check must judge it, not pass over it for
        the artifact-name beside it as a falsy fallback would.
        """
        maven = load_workflow(MAVEN)
        inputs = step_of(job_of(maven, "build"), SBOM_UPLOAD)["with"]
        inputs["artifact-name"] = inputs["name"]
        inputs["name"] = ""
        self.assert_check_fails(self.check_artefact_names, MAVEN, maven)

    def test_a_name_beside_artifact_ids_fails(self) -> None:
        """A download naming an artefact beside its ID fails the check."""
        maven = load_workflow(MAVEN)
        download = step_of(job_of(maven, "grype"), "Download SBOM artefact")
        download["with"]["name"] = "sbom-files-maven" + SUFFIX
        self.assert_check_fails(self.check_artefact_names, MAVEN, maven)

    def test_an_id_from_elsewhere_fails(self) -> None:
        """A download by an ID that is no upload's artifact-id fails."""
        maven = load_workflow(MAVEN)
        download = step_of(job_of(maven, "grype"), "Download SBOM artefact")
        download["with"]["artifact-ids"] = "${{ inputs.sbom_artifact_id }}"
        self.assert_check_fails(self.check_artefact_names, MAVEN, maven)
        download["with"]["artifact-ids"] = (
            "${{ needs.build.outputs.coverage }}"
        )
        self.assert_check_fails(self.check_artefact_names, MAVEN, maven)

    def test_an_id_from_no_upload_fails(self) -> None:
        """A job output naming a step that is no upload fails the check."""
        maven = load_workflow(MAVEN)
        job_of(maven, "build")["outputs"]["sbom_artifact_id"] = (
            "${{ steps.sbom.outputs.artifact-id }}"
        )
        self.assert_check_fails(self.check_artefact_names, MAVEN, maven)

    def test_a_second_step_under_the_upload_id_fails(self) -> None:
        """A second step carrying the upload's id fails the check.

        Before the upload and after it: the check cannot tell the two
        apart, and must settle for neither the first nor the last.
        """
        for position in ("before", "after"):
            with self.subTest(position=position):
                maven = load_workflow(MAVEN)
                build = job_of(maven, "build")
                upload_id = step_of(build, SBOM_UPLOAD)["id"]
                other = {
                    "name": "Not an upload",
                    "id": upload_id,
                    "run": "true",
                }
                index = 0 if position == "before" else len(steps_of(build))
                steps_of(build).insert(index, other)
                self.assert_check_fails(
                    self.check_artefact_names, MAVEN, maven
                )


class CellEvidence(ContractCase):
    """Lanes: a cell publishes only evidence a re-run replaces.

    The compatibility checks in testing.yaml download every cell's
    artefacts by pattern, so each upload they read must replace its
    cell's earlier one when the cell is re-run; otherwise a failed
    attempt's upload survives beside the new one and the check reads
    both. The overwrite holds only with a suffix: without one, two
    calls in a run share a name, and an overwrite would delete the
    other call's upload, which its Grype job fetches by ID.

    A toolchain record describes the build tool the cell provisioned,
    so it is taken only when every step before it succeeded; after a
    failed setup it would record whatever the runner image carries.
    """

    def cell_names(self, testing: Workflow) -> set[str]:
        """Return each artefact name prefix a compatibility check reads."""
        names: set[str] = set()
        for mapping in mappings(testing):
            match = CELL_PATTERN.fullmatch(text(mapping.get("pattern")))
            if match is not None:
                names.update(match.group(1).split(","))
        self.assertTrue(names, f"{TESTING}: found no cell patterns")
        return names

    def check_overwrite(
        self, testing: Workflow, lanes: dict[str, Workflow]
    ) -> None:
        """Fail unless every upload a check reads overwrites per cell."""
        for prefix in sorted(self.cell_names(testing)):
            name = prefix + SUFFIX
            uploads = [
                (path, step)
                for path, workflow in lanes.items()
                for job in jobs_of(workflow).values()
                for step in steps_of(job)
                if is_action(step, "actions/upload-artifact")
                and text(with_of(step).get("name")) == name
            ]
            self.assertTrue(
                uploads, f"{TESTING} reads '{name}', which no lane uploads"
            )
            for path, step in uploads:
                self.assertEqual(
                    text(with_of(step).get("overwrite")),
                    OVERWRITE,
                    f"{path}: '{text(step.get('name'))}' uploads '{name}'"
                    " without replacing a re-run cell's earlier upload",
                )

    def check_record(self, path: str, workflow: Workflow) -> None:
        """Fail unless the toolchain record waits for a successful build."""
        build = job_of(workflow, "build")
        self.assertEqual(
            text(step_of(build, RECORD).get("if")),
            RECORD_IF,
            f"{path}: '{RECORD}' runs after a failed step",
        )
        self.assertIn(
            RECORDED,
            text(step_of(build, RECORD_UPLOAD).get("if")),
            f"{path}: '{RECORD_UPLOAD}' does not wait for the record",
        )

    def lanes(self) -> dict[str, Workflow]:
        """Return each lane workflow by path."""
        return {path: load_workflow(path) for path in LANES}

    def test_every_cell_upload_overwrites(self) -> None:
        """Each upload a compatibility check reads overwrites per cell."""
        self.check_overwrite(load_workflow(TESTING), self.lanes())

    def test_an_upload_without_overwrite_fails(self) -> None:
        """Removing or hard-coding one upload's overwrite fails."""
        for path, name in (
            (MAVEN, RECORD_UPLOAD),
            (MAVEN, JUNIT_UPLOAD),
            (MAVEN, SBOM_UPLOAD),
            (GRADLE, RECORD_UPLOAD),
            (GRADLE, JUNIT_UPLOAD),
            (GRADLE, SBOM_UPLOAD),
            (MERGE, RECORD_UPLOAD),
            (MERGE, M2REPO_UPLOAD),
        ):
            for value in (None, True):
                with self.subTest(workflow=path, step=name, value=value):
                    lanes = self.lanes()
                    build = job_of(lanes[path], "build")
                    inputs = with_of(step_of(build, name))
                    inputs.pop("overwrite", None)
                    if value is not None:
                        inputs["overwrite"] = value
                    self.assert_check_fails(
                        self.check_overwrite, load_workflow(TESTING), lanes
                    )

    def test_a_pattern_no_lane_uploads_fails(self) -> None:
        """A check reading a name no lane uploads fails."""
        testing = load_workflow(TESTING)
        job = job_of(testing, "compatibility-gradle-check")
        step = step_of(job, "Download every cell")
        step["with"]["pattern"] = "{gradle-toolchain,gradle-other}-gradle-*"
        self.assert_check_fails(self.check_overwrite, testing, self.lanes())

    def test_every_record_waits_for_success(self) -> None:
        """Each lane records its toolchain only after a successful build."""
        for path in LANES:
            with self.subTest(workflow=path):
                self.check_record(path, load_workflow(path))

    def test_a_record_after_a_failure_fails(self) -> None:
        """A record taken whatever came before it fails the check."""
        for path in LANES:
            with self.subTest(workflow=path):
                workflow = load_workflow(path)
                step_of(job_of(workflow, "build"), RECORD)["if"] = (
                    "${{ !cancelled() && inputs.artifact_suffix != '' }}"
                )
                self.assert_check_fails(self.check_record, path, workflow)

    def test_an_upload_not_waiting_for_the_record_fails(self) -> None:
        """An upload that does not wait for the record fails the check."""
        for path in LANES:
            with self.subTest(workflow=path):
                workflow = load_workflow(path)
                step_of(job_of(workflow, "build"), RECORD_UPLOAD)["if"] = (
                    "${{ !cancelled() }}"
                )
                self.assert_check_fails(self.check_record, path, workflow)


class LatestAttemptWiring(ContractCase):
    """testing.yaml: the compatibility checks read each cell's last try.

    A re-run replaces a cell's artefacts only when the cell uploads
    again, so a cell that passed and then failed before uploading
    leaves the passing attempt's artefacts behind. Each aggregator
    therefore reads the run's jobs, as their latest attempts left
    them, before its record checks, which takes ``actions: read`` on
    that job alone; the lanes every consumer calls ask for nothing new.
    """

    def check_aggregator(self, testing: Workflow, job_id: str) -> None:
        """Fail unless ``job_id`` reads the latest builds, then checks."""
        job = job_of(testing, job_id)
        permissions: dict[str, object] = job.get("permissions") or {}
        self.assertEqual(
            text(permissions.get("actions")),
            "read",
            f"{job_id}: cannot read the run's jobs without actions: read",
        )
        reading = step_index(job, READ_BUILDS)
        self.assertGreaterEqual(reading, 0, f"{job_id}: no '{READ_BUILDS}'")
        self.assertGreater(
            step_index(job, ASSERT_CELLS),
            reading,
            f"{job_id}: '{ASSERT_CELLS}' runs before '{READ_BUILDS}'",
        )
        read = run_of(testing, job_id, READ_BUILDS)
        for needed in ("filter=latest", "{name, conclusion}", JOBS_FILE):
            self.assertIn(needed, read, f"{job_id}: '{READ_BUILDS}'")
        asserting = run_of(testing, job_id, ASSERT_CELLS)
        self.assertIn(
            f"bash {LATEST_CHECK} ",
            asserting,
            f"{job_id}: '{ASSERT_CELLS}' does not judge the latest builds",
        )
        self.assertIn(JOBS_FILE, asserting, f"{job_id}: '{ASSERT_CELLS}'")
        self.assertNotIn(
            "compatibility-check.sh",
            asserting,
            f"{job_id}: '{ASSERT_CELLS}' reads records without the builds",
        )

    def check_lanes(self, lanes: dict[str, Workflow]) -> None:
        """Fail when a lane asks for any actions permission."""
        for path, workflow in lanes.items():
            for mapping in mappings(workflow):
                permissions: object = mapping.get("permissions")
                if isinstance(permissions, dict) and "actions" in permissions:
                    self.fail(f"{path}: asks for an actions permission")

    @unittest.expectedFailure
    def test_every_aggregator_reads_the_latest_builds_first(self) -> None:
        """Both compatibility checks read the builds before the records."""
        testing = load_workflow(TESTING)
        for job_id in AGGREGATORS:
            with self.subTest(job=job_id):
                self.check_aggregator(testing, job_id)

    def test_an_aggregator_without_actions_read_fails(self) -> None:
        """Dropping the aggregator's actions: read fails the check."""
        for job_id in AGGREGATORS:
            with self.subTest(job=job_id):
                testing = load_workflow(TESTING)
                job_of(testing, job_id)["permissions"].pop("actions", None)
                self.assert_check_fails(self.check_aggregator, testing, job_id)

    def test_reading_the_builds_after_the_records_fails(self) -> None:
        """Reading the builds after the record checks fails the check."""
        for job_id in AGGREGATORS:
            with self.subTest(job=job_id):
                testing = load_workflow(TESTING)
                steps = steps_of(job_of(testing, job_id))
                read = steps.pop(
                    step_index(job_of(testing, job_id), READ_BUILDS)
                )
                steps.append(read)
                self.assert_check_fails(self.check_aggregator, testing, job_id)

    def test_a_record_check_without_the_builds_fails(self) -> None:
        """Calling a record check script directly fails the check."""
        for job_id, script in (
            (
                "compatibility-check",
                (
                    "bash .github/scripts/compatibility-check.sh "
                    '"${LANE}" cells "${MAVEN}" "${JAVA}"'
                ),
            ),
            (
                "compatibility-gradle-check",
                (
                    "bash .github/scripts/gradle-compatibility-check.sh "
                    'cells "${CELLS}"'
                ),
            ),
        ):
            with self.subTest(job=job_id):
                testing = load_workflow(TESTING)
                step_of(job_of(testing, job_id), ASSERT_CELLS)["run"] = script
                self.assert_check_fails(self.check_aggregator, testing, job_id)

    def test_no_lane_asks_for_actions(self) -> None:
        """The lanes every consumer calls hold no actions permission."""
        self.check_lanes({path: load_workflow(path) for path in LANES})

    def test_a_lane_asking_for_actions_fails(self) -> None:
        """A lane build job granted actions: read fails the check."""
        for path in LANES:
            with self.subTest(workflow=path):
                workflow = load_workflow(path)
                job_of(workflow, "build")["permissions"]["actions"] = "read"
                self.assert_check_fails(self.check_lanes, {path: workflow})


@needs_runner_tools
class LatestAttemptCheck(ContractCase):
    """latest-attempt-check.sh: a cell is judged by its latest build.

    Each test lays out one cell's artefacts as the aggregator downloads
    them, and a jobs file naming the cell's build job as testing.yaml
    and the lane name it, so a renamed job fails here rather than
    failing every cell in the run.
    """

    MAVEN_LINE = "3.9"
    MAVEN_VERSION = "3.9.11"
    GRADLE_LINE = "8.14"
    GRADLE_VERSION = "8.14.3"
    JAVA = "17"

    def build_job(self, caller: str, matrix: dict[str, str]) -> str:
        """Return the run's name for ``caller``'s build job on a cell."""
        job = job_of(load_workflow(TESTING), caller)
        name = text(job.get("name"))
        for key, value in matrix.items():
            name = name.replace(f"${{{{ matrix.{key} }}}}", value)
        self.assertNotIn("${{", name, f"{caller}: unrendered name")
        lane = load_workflow(text(job.get("uses")).removeprefix("$/"))
        return f"{name} / {text(job_of(lane, 'build').get('name'))}"

    def maven_job(self, lane: str) -> str:
        """Return the cell's build job name in a Maven lane."""
        caller = (
            "compatibility-merge"
            if lane == "merge"
            else ("compatibility-verify")
        )
        return self.build_job(
            caller, {"maven.line": self.MAVEN_LINE, "java": self.JAVA}
        )

    def gradle_job(self) -> str:
        """Return the cell's build job name in the Gradle lane."""
        return self.build_job(
            "compatibility-gradle",
            {"gradle.line": self.GRADLE_LINE, "java": self.JAVA},
        )

    @staticmethod
    def write_sbom(path: Path) -> None:
        """Write an SBOM carrying the fixture's resolved dependencies."""
        path.mkdir(parents=True)
        components = ",".join(
            '{"group":"com.fasterxml.jackson.core",'
            f'"name":"{name}","version":"2.20.0"}}'
            for name in ("jackson-databind", "jackson-core")
        )
        (path / "sbom-cyclonedx.json").write_text(
            f'{{"components":[{components}]}}', encoding="utf-8"
        )

    def write_verify_cell(self, cells: Path) -> None:
        """Write a passing verify cell's artefacts under ``cells``."""
        suffix = f"-maven-{self.MAVEN_LINE}-java-{self.JAVA}"
        toolchain = cells / f"maven-toolchain{suffix}"
        toolchain.mkdir(parents=True)
        (toolchain / "toolchain.txt").write_text(
            f"Apache Maven {self.MAVEN_VERSION} (0000000)\n"
            f"Java version: {self.JAVA}.0.12, vendor: Eclipse Adoptium\n",
            encoding="utf-8",
        )
        reports = cells / f"maven-junit-reports{suffix}"
        reports.mkdir(parents=True)
        (reports / "TEST-Example.xml").write_text(
            '<property name="java.specification.version"'
            f' value="{self.JAVA}"/>\n',
            encoding="utf-8",
        )
        self.write_sbom(cells / f"sbom-files-maven{suffix}")

    def write_gradle_cell(self, cells: Path) -> None:
        """Write a passing Gradle cell's artefacts under ``cells``."""
        suffix = f"-gradle-{self.GRADLE_LINE}-java-{self.JAVA}"
        toolchain = cells / f"gradle-toolchain{suffix}"
        toolchain.mkdir(parents=True)
        (toolchain / "toolchain.txt").write_text(
            f"Gradle {self.GRADLE_VERSION}\n"
            f"Launcher JVM:  {self.JAVA}.0.12 (Eclipse Adoptium)\n",
            encoding="utf-8",
        )
        reports = cells / f"gradle-junit-reports{suffix}"
        reports.mkdir(parents=True)
        (reports / "TEST-Example.xml").write_text("<x/>\n", encoding="utf-8")
        self.write_sbom(cells / f"sbom-files-gradle{suffix}")

    def run_check(
        self,
        lane: str,
        jobs: dict[str, str],
        write: Callable[[Path], None] | None,
    ) -> Verdict:
        """Run the check on one cell of ``lane`` with ``jobs`` concluded."""
        with tempfile.TemporaryDirectory() as scratch:
            cells = Path(scratch) / "cells"
            cells.mkdir()
            if write is not None:
                write(cells)
            jobs_file = Path(scratch) / "jobs.json"
            jobs_file.write_text(
                "".join(
                    json.dumps({"name": name, "conclusion": conclusion}) + "\n"
                    for name, conclusion in jobs.items()
                ),
                encoding="utf-8",
            )
            if lane == "gradle":
                gradle = {
                    "line": self.GRADLE_LINE,
                    "version": self.GRADLE_VERSION,
                }
                arguments = [
                    json.dumps([{"gradle": gradle, "java": self.JAVA}])
                ]
            else:
                maven = {
                    "line": self.MAVEN_LINE,
                    "version": self.MAVEN_VERSION,
                }
                arguments = [json.dumps([maven]), json.dumps([self.JAVA])]
            command = shlex.join(
                [
                    "bash",
                    str(ROOT / LATEST_CHECK),
                    lane,
                    str(jobs_file),
                    str(cells),
                    *arguments,
                ]
            )
            return run_script(f"{command}\n", {}, cwd=ROOT)

    @unittest.expectedFailure
    def test_a_passing_latest_build_reads_the_records(self) -> None:
        """A cell whose latest build succeeded passes on good records."""
        for lane, job, write in (
            ("verify", self.maven_job("verify"), self.write_verify_cell),
            ("gradle", self.gradle_job(), self.write_gradle_cell),
        ):
            with self.subTest(lane=lane):
                verdict = self.run_check(lane, {job: "success"}, write)
                self.assert_passes(verdict, f"{lane}: passing cell")
                self.assertIn("All 1 ", verdict.log)

    @unittest.expectedFailure
    def test_a_passing_latest_build_with_bad_records_fails(self) -> None:
        """A succeeded build still goes through the record checks."""
        for lane, job in (
            ("verify", self.maven_job("verify")),
            ("merge", self.maven_job("merge")),
            ("gradle", self.gradle_job()),
        ):
            with self.subTest(lane=lane):
                verdict = self.run_check(lane, {job: "success"}, None)
                self.assert_fails(verdict, f"{lane}: no records")
                self.assertIn("no toolchain record", verdict.log)

    @unittest.expectedFailure
    def test_a_failed_latest_build_fails_over_old_records(self) -> None:
        """A cell whose latest build failed fails beside passing records."""
        for lane, job, write in (
            ("verify", self.maven_job("verify"), self.write_verify_cell),
            ("merge", self.maven_job("merge"), None),
            ("gradle", self.gradle_job(), self.write_gradle_cell),
        ):
            for conclusion in ("failure", "cancelled", "skipped"):
                with self.subTest(lane=lane, conclusion=conclusion):
                    verdict = self.run_check(lane, {job: conclusion}, write)
                    self.assert_fails(verdict, f"{lane}: {conclusion}")
                    self.assertIn(
                        f"its latest build concluded '{conclusion}'",
                        verdict.log,
                    )
                    self.assertNotIn("no toolchain record", verdict.log)

    @unittest.expectedFailure
    def test_a_cell_without_a_build_job_fails(self) -> None:
        """A cell whose build job is absent from the run fails."""
        for lane, write in (
            ("verify", self.write_verify_cell),
            ("gradle", self.write_gradle_cell),
        ):
            with self.subTest(lane=lane):
                verdict = self.run_check(
                    lane, {"Other / Build": "success"}, write
                )
                self.assert_fails(verdict, f"{lane}: no build job")
                self.assertIn("job in this run", verdict.log)


@needs_runner_tools
class ArtifactSuffixValidation(ContractCase):
    """Lanes: the artifact_suffix input is validated."""

    def scripts_of(self, workflow: Workflow) -> list[str]:
        """Return each lane job's 'Validate artifact_suffix' run block."""
        return [
            run_of(workflow, job_id, SUFFIX_STEP)
            for job_id, job in jobs_of(workflow).items()
            if find_step(job, SUFFIX_STEP) is not None
        ]

    def test_accepts_a_leading_dash_and_safe_characters(self) -> None:
        """A suffix of a dash and name-safe characters passes."""
        for path in LANES:
            for script in self.scripts_of(load_workflow(path)):
                for value in ("-maven-3.10-java-25", "-a", "-4.0_rc.7"):
                    with self.subTest(workflow=path, value=value):
                        verdict = run_script(
                            script, {"ARTIFACT_SUFFIX": value}
                        )
                        self.assert_passes(
                            verdict, f"{path}: suffix '{value}' accepted"
                        )

    def test_rejects_other_suffixes(self) -> None:
        """No dash, a bare dash, separators, spaces, length and breaks fail."""
        for path in LANES:
            scripts = self.scripts_of(load_workflow(path))
            self.assertTrue(scripts, f"{path}: no '{SUFFIX_STEP}' step")
            for script in scripts:
                for value in (
                    "maven",
                    "-",
                    "-a/b",
                    "-a b",
                    "-a:b",
                    "-" + "x" * 65,
                    "-a\n::warning::injected",
                ):
                    with self.subTest(workflow=path, value=value):
                        verdict = run_script(
                            script, {"ARTIFACT_SUFFIX": value}
                        )
                        self.assert_fails(
                            verdict, f"{path}: suffix '{value}' rejected"
                        )


def example_files() -> list[str]:
    """Return every example workflow, relative to the repository root."""
    examples = ROOT / "examples"
    return sorted(
        str(path.relative_to(ROOT))
        for pattern in ("*.yaml", "*.yml")
        for path in examples.rglob(pattern)
        if path.is_file()
    )


def yaml_uses(document: object) -> list[str]:
    """Return every ``uses`` value under a mapping of ``document``."""
    return [
        text(mapping["uses"])
        for mapping in mappings(document)
        if "uses" in mapping
    ]


class ZizmorPlaceholderIgnores(ContractCase):
    """Examples: zizmor placeholder ignores.

    The examples pin an all-zero placeholder SHA, which zizmor's
    impostor-commit rule reports. .github/zizmor.yml ignores it by base
    filename and line, and only an online run applies those entries,
    while the pre-commit hook runs zizmor offline. Nothing else notices
    when an edit moves a placeholder off its entry, so hold them to the
    examples here: every placeholder needs an entry, every entry must
    mark a placeholder in some example of that name, and no entry may
    land on a real 'uses:' line, whose impostor commit it would hide.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Read the examples' uses: lines and the ignore entries once."""
        super().setUpClass()
        cls.examples = example_files()
        cls.lines = {path: uses_lines(path) for path in cls.examples}
        rules = load_yaml(ZIZMOR_CONFIG)["rules"]["impostor-commit"]["ignore"]
        cls.entries = [text(entry) for entry in rules]

    examples: list[str]
    lines: dict[str, list[tuple[int, str]]]
    entries: list[str]

    def placeholders(
        self, lines: dict[str, list[tuple[int, str]]]
    ) -> dict[str, list[str]]:
        """Return base-name:line of each placeholder with its examples."""
        found: dict[str, list[str]] = {}
        for path, values in lines.items():
            for number, value in values:
                if PLACEHOLDER.search(value):
                    found.setdefault(f"{Path(path).name}:{number}", []).append(
                        path
                    )
        return found

    def check_lines_match_the_yaml(self, path: str) -> None:
        """Fail unless the uses: values read line by line are the YAML's.

        Otherwise a quoting or comment form it misreads would let a real
        reference pass as one the check ignores.
        """
        self.assertEqual(
            sorted(value for _, value in self.lines[path]),
            sorted(yaml_uses(load_yaml(path))),
            f"{path}: the 'uses:' values read line by line differ from the"
            " YAML's; this check cannot judge the file",
        )

    def check_entries_mark_placeholders(
        self,
        lines: dict[str, list[tuple[int, str]]],
        entries: list[str],
    ) -> None:
        """Fail unless each entry marks a placeholder, hiding no real line."""
        placeholders = self.placeholders(lines)
        self.assertTrue(
            placeholders,
            "examples/: found no placeholder SHA to check the ignores against",
        )
        for entry in entries:
            match = re.fullmatch(r"([^:/]+):([0-9]+)", entry)
            self.assertIsNotNone(
                match,
                f"{ZIZMOR_CONFIG}: impostor-commit entry '{entry}' is not"
                " <file name>:<line>",
            )
            assert match is not None
            name, number = match.group(1), int(match.group(2))
            self.assertIn(
                entry,
                placeholders,
                f"{ZIZMOR_CONFIG}: impostor-commit entry '{entry}' marks no"
                f" placeholder in any example named {name}",
            )
            for path, values in lines.items():
                if Path(path).name != name:
                    continue
                for line, value in values:
                    if line == number:
                        self.assertIsNotNone(
                            PLACEHOLDER.search(value),
                            f"{ZIZMOR_CONFIG}: impostor-commit entry '{entry}'"
                            f" would hide a real 'uses:' at {path}:{number}",
                        )

    def check_placeholders_have_entries(
        self,
        lines: dict[str, list[tuple[int, str]]],
        entries: list[str],
    ) -> None:
        """Fail unless every placeholder has an ignore entry."""
        for key, holders in sorted(self.placeholders(lines).items()):
            self.assertIn(
                key,
                entries,
                f"{ZIZMOR_CONFIG}: no impostor-commit entry '{key}' for the"
                f" placeholder in {' '.join(holders)}",
            )

    def test_examples_exist(self) -> None:
        """There are example workflows to check."""
        self.assertTrue(self.examples, "examples/: found no example workflows")

    def test_lines_match_the_yaml(self) -> None:
        """Each example's uses: lines read as the YAML holds them."""
        for path in self.examples:
            with self.subTest(example=path):
                self.check_lines_match_the_yaml(path)

    def test_entries_mark_placeholders(self) -> None:
        """Every ignore entry marks a placeholder and hides no real line."""
        self.check_entries_mark_placeholders(self.lines, self.entries)

    def test_placeholders_have_entries(self) -> None:
        """Every placeholder has an ignore entry."""
        self.check_placeholders_have_entries(self.lines, self.entries)

    def test_an_entry_on_a_real_line_fails(self) -> None:
        """An entry whose line holds a real uses: fails the check."""
        path = next(
            p
            for p, values in self.lines.items()
            if any(not PLACEHOLDER.search(v) for _, v in values)
        )
        line = next(
            n for n, v in self.lines[path] if not PLACEHOLDER.search(v)
        )
        entries = [*self.entries, f"{Path(path).name}:{line}"]
        self.assert_check_fails(
            self.check_entries_mark_placeholders, self.lines, entries
        )

    def test_a_malformed_entry_fails(self) -> None:
        """An entry that is no <file name>:<line> fails the check."""
        entries = [*self.entries, "examples/github.yaml:43"]
        self.assert_check_fails(
            self.check_entries_mark_placeholders, self.lines, entries
        )

    def test_a_moved_placeholder_fails(self) -> None:
        """A placeholder moved off its entry fails the check.

        Only the entry check for the new line can fire: an example of
        the same base name may still hold a placeholder on the old one.
        """
        path, values = next(iter(self.lines.items()))
        number, value = next(
            (n, v) for n, v in values if PLACEHOLDER.search(v)
        )
        moved = {
            **self.lines,
            path: [
                (number + 1, value) if n == number else (n, v)
                for n, v in values
            ],
        }
        self.assert_check_fails(
            self.check_placeholders_have_entries, moved, self.entries
        )


if __name__ == "__main__":
    unittest.main()
