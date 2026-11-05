# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Shared readers for the workflow contract tests.

The tests read the reusable workflows as PyYAML parses them and run
the guard steps they extract from them. The helpers here keep the test
modules to their assertions: one place loads a workflow and walks its
jobs and steps. ``yaml_loading`` holds the strict parse, and
``guards`` the runner that executes a guard step and the probe for
what it needs.
"""

from __future__ import annotations

import copy
import re
import unittest
from collections.abc import Callable, Iterator, Mapping
from typing import Any, cast

from yaml_loading import load_yaml, read_text

MAVEN = ".github/workflows/maven-build-test.yaml"
GRADLE = ".github/workflows/gradle-build-test.yaml"
MERGE = ".github/workflows/maven-merge.yaml"
TESTING = ".github/workflows/testing.yaml"

CHECKOUT_ACTIONS = (
    "actions/checkout",
    "lfreleng-actions/checkout-gerrit-change-action",
)
GERRIT_CHECKOUT = "lfreleng-actions/checkout-gerrit-change-action"

# The steps the tests run as extracted from the workflows.
POM_GUARD = "Require the POM the SBOM resolves"
ENV_GUARD = "Require an environment the SBOM can reproduce"
LOCATE = "Locate the POM for metadata"
INIT_STEP = "Initialise Gerrit change submodules"
GATE_VALIDATE = "Validate Grype gate inputs"
SUFFIX_STEP = "Validate artifact_suffix"
MERGE_ENV_GUARD = "Require one environment for fetch, deploy and SBOM"
BUDGET = "Budget the SBOM step"
VALIDATE = "Validate inputs"
EXPAND = "Expand workspace placeholders"
CLEAN = "Require a clean m2repo"
STALE = "Refuse a stale m2repo"
LANDED = "Check the deploy landed in the m2repo"


Workflow = dict[str, Any]
Job = dict[str, Any]
Step = dict[str, Any]

_WORKFLOW_CACHE: dict[str, Workflow] = {}


def load_workflow(path: str) -> Workflow:
    """Return the workflow at ``path``, loaded once and deep-copied.

    PyYAML reads a bare ``on`` key as the boolean ``True``; it is
    renamed back so the tests can read the triggers by name. Each call
    returns its own copy, so a test may mutate it freely.
    """
    if path not in _WORKFLOW_CACHE:
        document = load_yaml(path)
        if True in document:
            document["on"] = document.pop(True)
        _WORKFLOW_CACHE[path] = document
    return copy.deepcopy(_WORKFLOW_CACHE[path])


def jobs_of(workflow: Workflow) -> dict[str, Job]:
    """Return the jobs of ``workflow`` by ID, failing on a non-mapping."""
    return section(workflow, "jobs")


def job_of(workflow: Workflow, job_id: str) -> Job:
    """Return job ``job_id`` of ``workflow``, failing when it is absent."""
    jobs = jobs_of(workflow)
    if job_id not in jobs:
        raise AssertionError(f"no job {job_id!r}; found {sorted(jobs)}")
    return jobs[job_id]


def steps_of(job: Job) -> list[Step]:
    """Return the steps of ``job``, or none for a job calling a workflow.

    Fails when ``steps:`` is written and is not a list.
    """
    steps = job.get("steps")
    if steps is None:
        return []
    if not isinstance(steps, list):
        raise AssertionError(f"steps: is {type(steps).__name__}, not a list")
    return cast("list[Step]", steps)


def only(
    matches: list[tuple[int, Step]], what: str
) -> tuple[int, Step] | None:
    """Return the one indexed step in ``matches``, or ``None`` for none.

    Step names need not be unique and the shell checks never chose
    between two: their ``yq`` printed every match and the comparison
    failed on the lot. Two or more matches fail here the same way,
    rather than let the first hide a second that drifted.
    """
    if len(matches) > 1:
        positions = [index for index, _ in matches]
        raise AssertionError(
            f"{len(matches)} steps {what} at positions {positions}; the"
            " check cannot tell which one the job means"
        )
    return matches[0] if matches else None


def steps_named(job: Job, name: str) -> list[tuple[int, Step]]:
    """Return each step of ``job`` named ``name``, with its position."""
    return [
        (index, step)
        for index, step in enumerate(steps_of(job))
        if step.get("name") == name
    ]


def find_step(job: Job, name: str) -> Step | None:
    """Return the step of ``job`` named ``name``, or ``None`` for none.

    Fails when more than one step carries the name.
    """
    found = only(steps_named(job, name), f"named {name!r}")
    return None if found is None else found[1]


def step_of(job: Job, name: str) -> Step:
    """Return the step of ``job`` named ``name``, failing when absent.

    Fails when more than one step carries the name.
    """
    step = find_step(job, name)
    if step is None:
        names = [step.get("name") for step in steps_of(job)]
        raise AssertionError(f"no step {name!r}; found {names}")
    return step


def step_index(job: Job, name: str) -> int:
    """Return the position of the step named ``name`` in ``job``, or -1.

    Fails when more than one step carries the name.
    """
    found = only(steps_named(job, name), f"named {name!r}")
    return -1 if found is None else found[0]


def step_with_id(job: Job, step_id: str) -> Step | None:
    """Return the step of ``job`` with ``id`` ``step_id``, or ``None``.

    Fails when more than one step carries the ID, as the shell check's
    ``yq`` did when it printed both steps' ``uses:`` for the one ID.
    """
    matches = [
        (index, step)
        for index, step in enumerate(steps_of(job))
        if step.get("id") == step_id
    ]
    found = only(matches, f"with id {step_id!r}")
    return None if found is None else found[1]


def uses_of(step: Step) -> str:
    """Return the ``uses:`` of ``step``, or an empty string."""
    return text(step.get("uses"))


def is_action(step: Step, *actions: str) -> bool:
    """Return whether ``step`` runs one of ``actions`` at any ref."""
    uses = uses_of(step)
    return any(uses.startswith(f"{action}@") for action in actions)


def with_of(step: Step) -> dict[str, Any]:
    """Return the ``with:`` inputs of ``step``, or an empty mapping."""
    return section(step, "with")


def needs_of(job: Job) -> list[str]:
    """Return the jobs ``job`` needs, whether written as one or a list."""
    needs = job.get("needs")
    if needs is None:
        return []
    if isinstance(needs, str):
        return [needs]
    return [text(need) for need in needs]


def text(value: object) -> str:
    """Return ``value`` as the shell checks read it.

    They compared the output of ``yq -r`` inside ``$(...)``: a missing
    value is empty, a boolean is ``true`` or ``false``, a number is its
    digits, and command substitution strips trailing newlines, which
    a ``|`` block scalar carries.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).rstrip("\n")


def scalars(value: object) -> Iterator[object]:
    """Yield every scalar under ``value``, as yq's ``..`` walks it."""
    if isinstance(value, dict):
        for child in cast("dict[object, object]", value).values():
            yield from scalars(child)
    elif isinstance(value, list):
        for child in cast("list[object]", value):
            yield from scalars(child)
    else:
        yield value


def mappings(value: object) -> Iterator[dict[str, Any]]:
    """Yield every mapping under ``value``, including ``value`` itself."""
    if isinstance(value, dict):
        mapping = cast("dict[str, Any]", value)
        yield mapping
        for child in mapping.values():
            yield from mappings(child)
    elif isinstance(value, list):
        for child in cast("list[object]", value):
            yield from mappings(child)


def section(mapping: Mapping[str, Any], key: str) -> dict[str, Any]:
    """Return the mapping under ``key``, or an empty one when absent.

    Fails when ``key`` is written and holds anything but a mapping,
    rather than read an empty one in its place.
    """
    value = mapping.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise AssertionError(
            f"{key}: is {type(value).__name__}, not a mapping"
        )
    return cast("dict[str, Any]", value)


def present(mapping: Mapping[str, Any], *keys: str) -> object:
    """Return the value under the first of ``keys`` written and not null.

    What jq's ``//`` chain in the shell checks read: a key written with
    an empty string is present, and its empty string is the value,
    where Python's ``or`` would pass it over for the next key.
    """
    for key in keys:
        value = mapping.get(key)
        if value is not None:
            return value
    return None


def outputs_of(job: Job) -> dict[str, Any]:
    """Return the ``outputs:`` of ``job``, or an empty mapping."""
    return section(job, "outputs")


def env_of(step: Step) -> dict[str, Any]:
    """Return the ``env:`` of ``step``, or an empty mapping."""
    return section(step, "env")


class Verdict:
    """What one run of an extracted ``run:`` block produced."""

    def __init__(self, returncode: int, log: str, output: str) -> None:
        self.returncode = returncode
        self.log = log
        self.output = output

    @property
    def passed(self) -> bool:
        """Return whether the script exited zero."""
        return self.returncode == 0

    def value(self, name: str) -> str:
        """Return output ``name`` as written in the ``name=value`` form.

        Every such line counts, joined by line breaks, as
        ``sed -n "s/^name=//p"`` printed them.
        """
        prefix = f"{name}="
        return "\n".join(
            line[len(prefix) :]
            for line in self.output.splitlines()
            if line.startswith(prefix)
        )

    def heredoc(self, name: str) -> str:
        """Return output ``name`` written in the ``name<<delimiter`` form."""
        lines = self.output.splitlines()
        opener = f"{name}<<"
        for index, line in enumerate(lines):
            if line.startswith(opener):
                delimiter = line[len(opener) :]
                body: list[str] = []
                for later in lines[index + 1 :]:
                    if later == delimiter:
                        break
                    body.append(later)
                return "\n".join(body)
        return ""

    def warned(self) -> bool:
        """Return whether a log line started a ``::warning::`` command."""
        return any(
            line.startswith("::warning::") for line in self.log.splitlines()
        )


def run_of(workflow: Workflow, job_id: str, name: str) -> str:
    """Return the ``run:`` block of step ``name`` in job ``job_id``."""
    step = step_of(job_of(workflow, job_id), name)
    run = step.get("run")
    if not isinstance(run, str) or not run:
        raise AssertionError(f"{job_id}: {name!r} has no run block")
    return run


def uses_lines(path: str) -> list[tuple[int, str]]:
    """Return each ``uses:`` value of the file at ``path`` with its line.

    Lines are numbered as zizmor numbers them. Each value is read alone,
    with any trailing YAML comment (a ``#`` after whitespace) stripped,
    so a real reference that names a placeholder in its comment still
    counts as real.
    """
    found: list[tuple[int, str]] = []
    pattern = re.compile(r"^\s*(?:-\s+)?uses:\s*(.*)$")
    for number, line in enumerate(read_text(path).splitlines(), start=1):
        match = pattern.match(line)
        if match is None:
            continue
        value = re.sub(r"\s+#.*$", "", match.group(1))
        found.append((number, value))
    return found


class ContractCase(unittest.TestCase):
    """A test case holding the workflows to their wiring.

    Every structural check is a method taking the workflow it judges,
    so a test can hand it the real workflow and expect it to pass, or a
    mutated copy and expect it to fail. ``maxDiff`` is off: the diffs
    of two whole steps are the message.
    """

    maxDiff = None

    def assert_passes(self, verdict: Verdict, label: str) -> None:
        """Fail unless ``verdict`` passed, quoting its log."""
        self.assertTrue(
            verdict.passed, f"{label}: expected pass, got fail\n{verdict.log}"
        )

    def assert_fails(self, verdict: Verdict, label: str) -> None:
        """Fail unless ``verdict`` failed, quoting its log."""
        self.assertFalse(
            verdict.passed, f"{label}: expected fail, got pass\n{verdict.log}"
        )

    def assert_check_fails(
        self, check: Callable[..., None], *args: object
    ) -> None:
        """Fail unless ``check(*args)`` raises an assertion."""
        with self.assertRaises(AssertionError):
            check(*args)
