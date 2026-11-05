# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Running a guard step extracted from a workflow, and what it needs.

A guard is a ``run:`` block the tests extract from a workflow and run
through bash. The guards are written for ``ubuntu-latest``; the tools
stock macOS lacks are listed in ``RUNNER_TOOLS`` and probed once, and
a test that runs a guard is skipped by name where one is absent.
"""

from __future__ import annotations

import functools
import os
import shutil
import subprocess
import tempfile
import unittest
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TypeVar

from helpers import Verdict

# What the guards need beyond git, bash and POSIX tools, which every
# supported developer host has. Each entry names the guard that needs
# it: GNU date -d, the two lanes' 'Validate Grype gate inputs' reading
# the window start; bash 4, the merge lane's 'Validate inputs'
# lower-casing with ${name,,}; jq, the two environment guards reading
# their JSON. A guard that starts calling another tool extends this.
RUNNER_TOOLS = ("GNU date (date -d)", "bash 4 or later", "jq")


def missing_runner_tools(path: str | None = None) -> list[str]:
    """Return the entries of ``RUNNER_TOOLS`` the host lacks, each once.

    ``path`` replaces ``PATH`` for the probe, so a test can stand in
    another host's tools.
    """
    env = dict(os.environ)
    if path is not None:
        env["PATH"] = path
    missing: list[str] = []
    if probe(["date", "-u", "-d", "2026-01-01", "+%F"], env) != "2026-01-01":
        missing.append("GNU date (date -d)")
    major = probe(["bash", "-c", 'printf %s "${BASH_VERSINFO[0]}"'], env)
    if not major.isdigit() or int(major) < 4:
        missing.append(f"bash 4 or later (found {major or 'none'})")
    if shutil.which("jq", path=env.get("PATH")) is None:
        missing.append("jq (not on PATH)")
    return missing


def probe(command: list[str], env: Mapping[str, str]) -> str:
    """Return the stripped stdout of ``command``, or empty when it fails."""
    try:
        completed = subprocess.run(
            command,
            check=False,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="replace",
        )
    except OSError:
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout.strip()


@functools.cache
def host_missing_tools() -> tuple[str, ...]:
    """Return what this host lacks of the runner's tools, probed once."""
    return tuple(missing_runner_tools())


Decorated = TypeVar("Decorated", bound=Callable[..., object])


def needs_runner_tools(target: Decorated) -> Decorated:
    """Mark a test, or a class of them, that runs an extracted guard.

    The structural tests need nothing beyond Python; these need the
    runner's tools, and are skipped by name where they are absent,
    rather than pass falsely or fail on the host instead of the guard.
    """
    missing = host_missing_tools()
    skip = unittest.skipUnless(
        not missing,
        "runs a guard extracted from the workflows, which needs "
        + ", ".join(missing),
    )
    return skip(target)


def run_script(
    script: str,
    env: Mapping[str, str],
    cwd: Path | None = None,
) -> Verdict:
    """Run ``script`` through bash with ``env`` set over the environment.

    ``GITHUB_OUTPUT`` points at a fresh file, whose content the verdict
    carries; stdout and stderr land together in its log.
    """
    with tempfile.TemporaryDirectory() as scratch:
        path = Path(scratch) / "step.sh"
        path.write_text(script, encoding="utf-8")
        output = Path(scratch) / "output"
        output.touch()
        completed = subprocess.run(
            ["bash", str(path)],
            check=False,
            cwd=cwd,
            env={**os.environ, **env, "GITHUB_OUTPUT": str(output)},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
        return Verdict(
            completed.returncode,
            completed.stdout,
            output.read_text(encoding="utf-8"),
        )
