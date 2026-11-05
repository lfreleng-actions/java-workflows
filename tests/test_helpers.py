# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The lookups the contract tests share, on what the shell checks read.

The shell checks never chose between two matches: their ``yq`` printed
every one and the comparison failed on the lot. Each lookup in
``helpers`` keeps that, and each test here duplicates the entry it
looks up and expects the failure, so a lookup that starts settling
for the first match fails the suite. Nor did they pass over a value
written empty, or read a section of the wrong shape as an empty one;
the readers here are held to that too.
"""

from __future__ import annotations

import unittest

import yaml

from helpers import (
    GRADLE,
    MAVEN,
    MERGE,
    TESTING,
    Job,
    find_step,
    job_of,
    jobs_of,
    load_workflow,
    present,
    section,
    step_index,
    step_of,
    step_with_id,
    steps_of,
)
from yaml_loading import parse_yaml

STEP = "Require the POM the SBOM resolves"


def job_with(*steps: dict[str, str]) -> Job:
    """Return a job holding ``steps`` after an unrelated first step."""
    checkout = {"name": "Checkout", "uses": "actions/checkout@0"}
    return {"steps": [checkout, *steps]}


class StepsByName(unittest.TestCase):
    """``find_step``, ``step_of`` and ``step_index`` on a repeated name."""

    def setUp(self) -> None:
        """Hold one job with the step once and one with it twice."""
        self.once = job_with({"name": STEP, "run": "true"})
        self.twice = job_with(
            {"name": STEP, "run": "true"},
            {"name": STEP, "run": "true", "if": "always()"},
        )

    def test_find_step_returns_the_one_match(self) -> None:
        """One match is returned, and none is ``None``."""
        self.assertEqual(
            find_step(self.once, STEP), {"name": STEP, "run": "true"}
        )
        self.assertIsNone(find_step(self.once, "Absent"))

    def test_find_step_fails_on_two_matches(self) -> None:
        """A second step under the name fails rather than hide."""
        with self.assertRaisesRegex(AssertionError, "2 steps named"):
            find_step(self.twice, STEP)

    def test_step_of_fails_on_two_matches(self) -> None:
        """``step_of`` fails on a repeated name as it does on none."""
        self.assertEqual(step_of(self.once, STEP)["run"], "true")
        with self.assertRaisesRegex(AssertionError, "no step"):
            step_of(self.once, "Absent")
        with self.assertRaisesRegex(AssertionError, "2 steps named"):
            step_of(self.twice, STEP)

    def test_step_index_fails_on_two_matches(self) -> None:
        """``step_index`` gives the one position, -1 for none, else fails."""
        self.assertEqual(step_index(self.once, STEP), 1)
        self.assertEqual(step_index(self.once, "Absent"), -1)
        with self.assertRaisesRegex(AssertionError, "2 steps named"):
            step_index(self.twice, STEP)


class StepsById(unittest.TestCase):
    """``step_with_id`` on a repeated ``id``."""

    def test_the_one_step_is_returned(self) -> None:
        """One match is returned, and none is ``None``."""
        job = job_with({"id": "sbom", "uses": "actions/upload-artifact@0"})
        self.assertEqual(
            step_with_id(job, "sbom"),
            {"id": "sbom", "uses": "actions/upload-artifact@0"},
        )
        self.assertIsNone(step_with_id(job, "absent"))

    def test_two_steps_under_the_id_fail(self) -> None:
        """A second step carrying the id fails rather than hide."""
        job = job_with(
            {"id": "sbom", "run": "true"},
            {"id": "sbom", "uses": "actions/upload-artifact@0"},
        )
        with self.assertRaisesRegex(AssertionError, "2 steps with id"):
            step_with_id(job, "sbom")


class WrittenValues(unittest.TestCase):
    """The readers take a value as written, and fail on a wrong shape."""

    def test_present_keeps_an_empty_string(self) -> None:
        """A key written empty is present, as jq's ``//`` read it."""
        inputs = {"name": "", "artifact-name": "sbom-files"}
        self.assertEqual(present(inputs, "name", "artifact-name"), "")

    def test_present_passes_over_a_missing_or_null_key(self) -> None:
        """A key absent or written null gives way to the next."""
        self.assertEqual(
            present({"artifact-name": "sbom"}, "name", "artifact-name"),
            "sbom",
        )
        self.assertEqual(
            present(
                {"name": None, "artifact-name": "sbom"},
                "name",
                "artifact-name",
            ),
            "sbom",
        )
        self.assertIsNone(present({}, "name", "artifact-name"))

    def test_section_fails_on_a_non_mapping(self) -> None:
        """A section written as a scalar or list fails, absent is empty."""
        self.assertEqual(section({}, "with"), {})
        self.assertEqual(section({"with": None}, "with"), {})
        self.assertEqual(section({"with": {"a": 1}}, "with"), {"a": 1})
        for value in ("text", ["a"], 1):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(
                    AssertionError, "with: is .*, not a mapping"
                ),
            ):
                section({"with": value}, "with")

    def test_jobs_of_fails_on_a_non_mapping(self) -> None:
        """``jobs:`` written as a list fails rather than read as none."""
        self.assertEqual(jobs_of({}), {})
        with self.assertRaisesRegex(AssertionError, "jobs: is list"):
            jobs_of({"jobs": [{"build": {}}]})

    def test_steps_of_fails_on_a_non_list(self) -> None:
        """``steps:`` written as a mapping fails rather than read as none."""
        self.assertEqual(steps_of({}), [])
        self.assertEqual(steps_of({"uses": "x"}), [])
        with self.assertRaisesRegex(AssertionError, "steps: is dict"):
            steps_of({"steps": {"name": "a"}})


class MappingKeys(unittest.TestCase):
    """``parse_yaml`` on a key written twice, which keyed lookups ride on.

    Jobs, inputs and outputs are read by key, so a duplicate can only
    be caught before the mapping exists. ``job_of`` is the lookup the
    tests reach jobs through; a document with the job written twice
    never gets that far.
    """

    def test_a_document_without_duplicates_parses(self) -> None:
        """A well-formed document reads as ``safe_load`` reads it."""
        document = (
            "on:\n  workflow_call:\n    inputs:\n      a: {}\n"
            "jobs:\n  build: {}\n"
        )
        self.assertEqual(parse_yaml(document), yaml.safe_load(document))
        self.assertEqual(job_of(parse_yaml(document), "build"), {})

    def test_a_job_written_twice_fails(self) -> None:
        """A second ``jobs`` entry under one ID fails the parse."""
        document = "jobs:\n  build:\n    steps: []\n  build:\n    steps: []\n"
        with self.assertRaisesRegex(yaml.YAMLError, "duplicate key 'build'"):
            parse_yaml(document)

    def test_an_input_written_twice_fails(self) -> None:
        """A second ``inputs`` entry under one name fails the parse."""
        document = (
            "on:\n  workflow_call:\n    inputs:\n"
            "      grype_enabled: {default: true}\n"
            "      grype_enabled: {default: false}\n"
        )
        with self.assertRaisesRegex(
            yaml.YAMLError, "duplicate key 'grype_enabled'"
        ):
            parse_yaml(document)

    def test_a_top_level_key_written_twice_fails(self) -> None:
        """A second ``jobs`` mapping fails the parse, as GitHub's does."""
        document = "jobs:\n  build: {}\njobs:\n  test: {}\n"
        with self.assertRaisesRegex(yaml.YAMLError, "duplicate key 'jobs'"):
            parse_yaml(document)

    def test_a_bare_and_a_quoted_on_are_one_key(self) -> None:
        """``on`` and ``"on"`` both fail the parse, in either order.

        PyYAML tags a bare ``on`` as a boolean and a quoted one as a
        string, so by tag they differ; ``load_workflow`` renames the
        boolean to the string, so the second trigger section would
        bury the first with its inputs and outputs.
        """
        bare = "on:\n  workflow_call:\n    inputs:\n      a: {}\n"
        quoted = '"on":\n  workflow_call:\n    inputs:\n      b: {}\n'
        for document in (bare + quoted, quoted + bare):
            with (
                self.subTest(document=document),
                self.assertRaisesRegex(yaml.YAMLError, "duplicate key 'on'"),
            ):
                parse_yaml(document)

    def test_a_bare_on_is_read_as_the_trigger_section(self) -> None:
        """The top-level ``on`` alone may load as ``True``; nothing else."""
        self.assertEqual(
            parse_yaml("on:\n  push: {}\njobs: {}\n"),
            {True: {"push": {}}, "jobs": {}},
        )


class RetypedKeys(unittest.TestCase):
    """``parse_yaml`` on a key PyYAML reads as anything but its text.

    ``yaml.BaseLoader`` reads every key as the string written and
    ``yaml.SafeLoader`` retypes ``off``, ``no``, ``null``, ``~`` and a
    bare number; the lookups by name would never find such an entry,
    and two spellings of one value fold into one entry without a word.
    ``parse_yaml`` reads each document both ways and fails on the first
    key the two readings disagree on, naming its path.
    """

    def test_a_job_named_off_fails_with_its_path(self) -> None:
        """A job PyYAML reads as ``False`` fails rather than hide."""
        document = "jobs:\n  off:\n    steps: []\n"
        with self.assertRaisesRegex(
            AssertionError, "reads key 'off' at jobs.off as False"
        ):
            parse_yaml(document)

    def test_two_false_spellings_fail_in_either_order(self) -> None:
        """``off`` and ``no`` fold into one job; the first named fails.

        Without the guard, an unwired checkout in the first job never
        reaches the checkout contract, whichever order the two sit in.
        """
        off = "  off:\n    steps: []\n"
        no = "  no:\n    steps: [{uses: actions/checkout@0}]\n"
        for first, second, key in ((off, no, "off"), (no, off, "no")):
            document = "jobs:\n" + first + second
            with (
                self.subTest(first=key),
                self.assertRaisesRegex(
                    AssertionError, f"reads key '{key}' at jobs.{key}"
                ),
            ):
                parse_yaml(document)

    def test_every_retyped_spelling_fails(self) -> None:
        """Each spelling PyYAML retypes fails, wherever it sits."""
        for key, reading in (
            ("yes", "True"),
            ("Off", "False"),
            ("null", "None"),
            ("~", "None"),
            ("1", "1"),
            ("0x10", "16"),
            ("1.5", "1.5"),
        ):
            document = (
                f"on:\n  workflow_call:\n    inputs:\n      {key}: {{}}\n"
            )
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(
                    AssertionError,
                    f"reads key {key!r} at on.workflow_call.inputs.{key}"
                    f" as {reading}",
                ),
            ):
                parse_yaml(document)

    def test_a_retyped_key_in_a_sequence_is_found(self) -> None:
        """A key under a step in a list fails with the step's position."""
        document = (
            "jobs:\n  build:\n    steps:\n      - name: a\n"
            "      - with:\n          no: x\n"
        )
        with self.assertRaisesRegex(
            AssertionError, "at jobs.build.steps.1.with.no as False"
        ):
            parse_yaml(document)

    def test_a_second_true_spelling_beside_on_fails(self) -> None:
        """``yes`` after the tolerated ``on`` folds into it, and fails."""
        document = "on:\n  push: {}\nyes:\n  pull_request: {}\n"
        with self.assertRaisesRegex(
            AssertionError, "folds key 'yes' at yes into an earlier key"
        ):
            parse_yaml(document)

    def test_on_below_the_top_level_fails(self) -> None:
        """``on`` is tolerated at the top level alone."""
        document = "jobs:\n  on:\n    steps: []\n"
        with self.assertRaisesRegex(
            AssertionError, "reads key 'on' at jobs.on as True"
        ):
            parse_yaml(document)

    def test_a_quoted_spelling_parses(self) -> None:
        """Quoting keeps a key its text, so each quoted spelling parses."""
        document = "jobs:\n  'off': {}\n  'no': {}\n  'null': {}\n  '1': {}\n"
        self.assertEqual(
            list(parse_yaml(document)["jobs"]), ["off", "no", "null", "1"]
        )

    def test_the_shipped_workflows_pass_the_guard(self) -> None:
        """No key in the workflows under test is retyped today."""
        for path in (MAVEN, GRADLE, MERGE, TESTING):
            with self.subTest(path=path):
                self.assertIn("on", load_workflow(path))


if __name__ == "__main__":
    unittest.main()
