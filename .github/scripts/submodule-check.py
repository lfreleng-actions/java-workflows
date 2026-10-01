#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Assert from JUnit XML that the fixture's SubmoduleTest passed.

The fixtures' SubmoduleTest reads a file from their git submodule. It
passes when the submodule was checked out, fails when the content is
wrong, and is skipped when the directory is empty, so a consumer that
checks out without submodules still builds. A skip here therefore means
the lane's checkout left the submodule out, and must fail this check as
surely as a failure does.

Usage: submodule-check.py <junit-report-directory>
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# Matched as a prefix: Surefire appends its reportNameSuffix to the
# classname, as "SubmoduleTest(env-vars)".
CLASSNAME = "org.lfreleng.test.core.SubmoduleTest"


def parse_cases(root: Path) -> list[ET.Element]:
    """Return every SubmoduleTest test case under root.

    The reports come from this run's own build of an org-owned fixture,
    not from an untrusted party, so the standard library parser is
    acceptable here.
    """
    cases: list[ET.Element] = []
    for report in sorted(root.rglob("*.xml")):
        tree = ET.parse(report)  # noqa: S314 -- see docstring
        cases.extend(
            case
            for case in tree.iter("testcase")
            if case.get("classname", "").startswith(CLASSNAME)
        )
    return cases


def verdict(case: ET.Element) -> str:
    """Classify one test case as passed, skipped, failed or errored."""
    for outcome in ("skipped", "failure", "error"):
        if case.find(outcome) is not None:
            return outcome
    return "passed"


def main(argv: list[str]) -> int:
    """Check the reports and return the process exit status."""
    if len(argv) != 2:  # noqa: PLR2004 -- program name and one argument
        sys.stderr.write(__doc__ or "")
        return 2
    cases = parse_cases(Path(argv[1]))
    if not cases:
        print(
            f"::error::No {CLASSNAME} result in the reports. The fixture "
            "may predate the test, or the build stopped before it ran."
        )
        return 1
    status = 0
    for case in cases:
        outcome = verdict(case)
        name = case.get("name", "?")
        print(f"{case.get('classname')} {name}: {outcome}")
        if outcome == "skipped":
            print(
                "::error::SubmoduleTest was skipped: the checkout left the "
                "submodule out, so checkout_submodules did not take effect."
            )
            status = 1
        elif outcome != "passed":
            print(
                f"::error::SubmoduleTest {outcome}: the submodule was "
                "checked out but does not hold the pinned commit's content."
            )
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv))
