# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The suite on a host without the runner's tools.

The structural tests need Python and PyYAML alone. The tests that run a
guard extracted from the workflows need what ``ubuntu-latest`` has and
stock macOS lacks, bash 4 and ``jq``, and are skipped by name where
either is absent. These tests hold the probe behind that
skip to its word, by standing in each host's tools on ``PATH``, and
hold the Linux runner itself to skipping nothing. A developer's Linux
host is not that runner and gets the same skips macOS does. Git and
bash themselves are assumed, as every supported developer host has
them.
"""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path

from guards import (
    RUNNER_TOOLS,
    host_missing_tools,
    missing_runner_tools,
    probe,
)


def linux_runner(environ: Mapping[str, str]) -> bool:
    """Return whether ``environ`` is a Linux GitHub Actions runner's.

    GitHub sets ``GITHUB_ACTIONS`` to ``true`` and ``RUNNER_OS`` to the
    runner's platform on every runner; a developer's Linux host sets
    neither, and the platform alone cannot tell the two apart.
    """
    return (
        environ.get("GITHUB_ACTIONS") == "true"
        and environ.get("RUNNER_OS") == "Linux"
    )


def stub_path(
    scratch: str,
    bash: str = "printf 4",
    absent: tuple[str, ...] = (),
) -> str:
    """Stub the runner's tools into ``scratch`` and return it as PATH.

    ``jq`` gets a ``/bin/sh`` stub that exits zero, ``bash`` the given
    body, and the names in ``absent`` none, created here at run time.
    The path holds ``scratch`` alone, so a tool without a stub is
    missing.
    """
    bodies = {"bash": bash, "jq": "exit 0"}
    for name, body in bodies.items():
        if name in absent:
            continue
        stub = Path(scratch) / name
        stub.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    return scratch


class RunnerTools(unittest.TestCase):
    """The probe for the runner's tools."""

    def test_the_runner_has_every_tool(self) -> None:
        """On the Linux runner, where the workflows run, nothing is skipped."""
        if not linux_runner(os.environ):
            self.skipTest(
                "the runner's tools are required on the Linux GitHub"
                " Actions runner alone"
            )
        self.assertEqual(host_missing_tools(), ())

    def test_the_linux_runner_is_known_by_its_variables(self) -> None:
        """GitHub's own variables name the runner, not the platform."""
        self.assertTrue(
            linux_runner({"GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux"})
        )

    def test_another_runner_is_not_the_linux_one(self) -> None:
        """A macOS or Windows runner is held to nothing here."""
        for runner_os in ("macOS", "Windows"):
            with self.subTest(runner_os=runner_os):
                self.assertFalse(
                    linux_runner(
                        {"GITHUB_ACTIONS": "true", "RUNNER_OS": runner_os}
                    )
                )

    def test_a_developer_host_is_not_the_runner(self) -> None:
        """A Linux host outside GitHub Actions is skipped, not failed."""
        self.assertFalse(linux_runner({}))
        self.assertFalse(linux_runner({"RUNNER_OS": "Linux"}))

    def test_the_tools_are_found(self) -> None:
        """Every tool present, bash at 4, misses none."""
        with tempfile.TemporaryDirectory() as scratch:
            path = stub_path(scratch)
            self.assertEqual(missing_runner_tools(path), [])

    def test_a_missing_jq_is_named(self) -> None:
        """A jq absent, which the environment guards need, is named."""
        with tempfile.TemporaryDirectory() as scratch:
            path = stub_path(scratch, absent=("jq",))
            self.assertEqual(missing_runner_tools(path), ["jq (not on PATH)"])

    def test_bash_3_is_named(self) -> None:
        """A bash reporting 3, as macOS ships, is named with its version."""
        with tempfile.TemporaryDirectory() as scratch:
            path = stub_path(scratch, bash="printf 3")
            self.assertEqual(
                missing_runner_tools(path), ["bash 4 or later (found 3)"]
            )

    def test_every_shortfall_is_named(self) -> None:
        """Each entry of ``RUNNER_TOOLS`` is named when absent, in order."""
        with tempfile.TemporaryDirectory() as scratch:
            path = stub_path(scratch, bash="exit 127", absent=("jq",))
            missing = missing_runner_tools(path)
            self.assertEqual(
                missing,
                ["bash 4 or later (found none)", "jq (not on PATH)"],
            )
            for tool, named in zip(RUNNER_TOOLS, missing, strict=True):
                self.assertTrue(named.startswith(tool), (tool, named))

    def test_a_missing_command_is_empty(self) -> None:
        """A command PATH does not hold probes as empty, not an error."""
        with tempfile.TemporaryDirectory() as scratch:
            self.assertEqual(probe(["jq", "--version"], {"PATH": scratch}), "")


if __name__ == "__main__":
    unittest.main()
