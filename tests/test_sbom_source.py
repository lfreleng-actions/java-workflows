# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for the Maven verify lane's sbom_source input.

Under 'build' the lane merges the target/bom.json that makeBom wrote
into each module, rather than resolve the graph again. These tests run
the merge and the validation as extracted from the workflow and hold
the wiring that chooses between the two sources:

- sbom_source defaults to 'generate', and the validation job accepts
  'generate' and 'build' alone;
- the generate path, from the settings step on, runs only under
  'generate', and the merge only under 'build' after a successful
  build;
- the upload takes whichever SBOM the run produced, and the merge's
  JSON alone under 'build';
- the merge keeps one root with no edges of its own, each module once
  and unscoped (whatever type a sibling names it by), each other
  component once at its strongest scope, and every module's edges;
  it ignores a BOM in a target tree, outside a module or tracked by
  the repository, and fails on none, on a BOM without a schema
  version or on a mix of schemas.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from guards import run_script
from helpers import (
    MAVEN,
    ContractCase,
    Verdict,
    job_of,
    load_workflow,
    run_of,
    section,
    step_of,
    text,
)

MERGE_STEP = "Merge the build SBOMs"
SOURCE_VALIDATE = "Validate sbom_source"
SETTINGS_STEP = "Install Maven global settings"
UPLOAD_STEP = "Upload SBOM artifacts"
VALIDATE_JOB = "gerrit-validate"
REPOSITORY = "example/project"

API = "pkg:maven/org.example/api@1.0.0?type=jar"
IMPL = "pkg:maven/org.example/impl@1.0.0?type=jar"
GUAVA = "pkg:maven/com.google.guava/guava@33.0.0-jre?type=jar"
NETTY = "pkg:maven/io.netty/netty-common@4.2.2.Final?type=jar"


def module_bom(
    ref: str,
    components: list[dict[str, Any]],
    edges: dict[str, list[str]],
    spec: str = "1.6",
) -> dict[str, Any]:
    """Return a makeBom-shaped document for the module ``ref``."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec,
        "metadata": {
            "tools": {
                "components": [
                    {"type": "library", "name": "cyclonedx-maven-plugin"}
                ]
            },
            "component": {"type": "library", "bom-ref": ref, "name": ref},
        },
        "components": components,
        "dependencies": [
            {"ref": key, "dependsOn": value} for key, value in edges.items()
        ],
    }


def library(ref: str) -> dict[str, Any]:
    """Return a required library component named by ``ref``."""
    return {
        "type": "library",
        "bom-ref": ref,
        "name": ref,
        "scope": "required",
    }


def place(top: Path, module: str, bom: dict[str, Any] | None) -> None:
    """Write a module at ``top/module`` with ``bom`` as its target BOM."""
    directory = top / module
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "pom.xml").touch()
    if bom is not None:
        (directory / "target").mkdir(exist_ok=True)
        (directory / "target" / "bom.json").write_text(
            json.dumps(bom), encoding="utf-8"
        )


def reactor(top: Path) -> None:
    """Lay out a two-module reactor whose impl depends on its api."""
    place(top, ".", None)
    place(top, "api", module_bom(API, [library(GUAVA)], {API: [GUAVA]}))
    place(
        top,
        "impl",
        module_bom(
            IMPL,
            [library(API), library(GUAVA), library(NETTY)],
            {IMPL: [API, NETTY], API: [GUAVA], GUAVA: [], NETTY: []},
        ),
    )


class SbomMerge(ContractCase):
    """Build job: the merge of the module SBOMs, as extracted."""

    def merge(self, top: Path) -> Verdict:
        """Run the extracted merge step in ``top``."""
        script = run_of(load_workflow(MAVEN), "build", MERGE_STEP)
        return run_script(
            script,
            {"REPOSITORY": REPOSITORY},
            cwd=top,
        )

    def merged(self, top: Path) -> dict[str, Any]:
        """Return the document the merge wrote in ``top``."""
        path = top / "sbom-cyclonedx.json"
        document: dict[str, Any] = json.loads(path.read_text("utf-8"))
        return document

    def test_merges_the_modules_into_one_graph(self) -> None:
        """Each module once and unscoped, each library once, edges joined."""
        with tempfile.TemporaryDirectory() as scratch:
            top = Path(scratch)
            reactor(top)

            verdict = self.merge(top)

            self.assert_passes(verdict, "two module BOMs merge")
            document = self.merged(top)
            root = f"reactor:{REPOSITORY}"
            self.assertEqual(document["specVersion"], "1.6")
            self.assertEqual(
                section(document, "metadata")["component"]["bom-ref"], root
            )
            refs = [c["bom-ref"] for c in document["components"]]
            self.assertEqual(sorted(refs), sorted([API, IMPL, GUAVA, NETTY]))
            scoped = {
                c["bom-ref"]: c.get("scope") for c in document["components"]
            }
            self.assertEqual(scoped[API], None, "a sibling stays a module")
            self.assertEqual(scoped[GUAVA], "required")
            edges = {
                d["ref"]: d["dependsOn"] for d in document["dependencies"]
            }
            self.assertEqual(edges[root], [])
            self.assertEqual(edges[IMPL], [API, NETTY])
            self.assertEqual(edges[API], [GUAVA])

    def test_a_bundle_module_stays_one_module(self) -> None:
        """A sibling's ?type=jar names the ?type=bundle module once."""
        with tempfile.TemporaryDirectory() as scratch:
            top = Path(scratch)
            jar = API
            bundle = API.replace("type=jar", "type=bundle")
            place(top, "api", module_bom(bundle, [library(GUAVA)], {}))
            place(
                top,
                "impl",
                module_bom(
                    IMPL,
                    [library(jar), library(GUAVA)],
                    {IMPL: [jar], jar: [GUAVA], GUAVA: []},
                ),
            )

            verdict = self.merge(top)

            self.assert_passes(verdict, "a bundle module and its jar ref")
            document = self.merged(top)
            refs = [c["bom-ref"] for c in document["components"]]
            self.assertEqual(sorted(refs), sorted([bundle, IMPL, GUAVA]))
            edges = {
                d["ref"]: d["dependsOn"] for d in document["dependencies"]
            }
            self.assertNotIn(jar, edges)
            self.assertEqual(edges[IMPL], [bundle])
            self.assertEqual(edges[bundle], [GUAVA])

    def test_the_strongest_scope_wins(self) -> None:
        """A library two modules scope differently keeps the stronger."""
        cases = (
            ("optional", "required", "required"),
            ("required", "optional", "required"),
            ("excluded", "optional", "optional"),
            ("optional", None, None),
        )
        for first, second, expected in cases:
            with (
                self.subTest(first=first, second=second),
                tempfile.TemporaryDirectory() as scratch,
            ):
                top = Path(scratch)
                lib_a, lib_b = library(GUAVA), library(GUAVA)
                lib_a["scope"] = first
                if second is None:
                    del lib_b["scope"]
                else:
                    lib_b["scope"] = second
                place(top, "a", module_bom(API, [lib_a], {API: [GUAVA]}))
                place(top, "b", module_bom(IMPL, [lib_b], {IMPL: [GUAVA]}))

                verdict = self.merge(top)

                self.assert_passes(verdict, f"{first} beside {second}")
                scopes = {
                    c["bom-ref"]: c.get("scope")
                    for c in self.merged(top)["components"]
                }
                self.assertEqual(scopes[GUAVA], expected)

    def test_skips_a_bom_the_repository_tracks(self) -> None:
        """A committed target/bom.json is not the build's output."""
        with tempfile.TemporaryDirectory() as scratch:
            top = Path(scratch)
            reactor(top)
            place(top, "archived/old", module_bom(NETTY, [], {NETTY: []}))
            subprocess.run(
                ["git", "init", "-q", str(top)], check=True, timeout=30
            )
            subprocess.run(
                ["git", "-C", str(top), "add", "archived/old"],
                check=True,
                timeout=30,
            )

            verdict = self.merge(top)

            self.assert_passes(verdict, "a tracked BOM is skipped")
            refs = [c["bom-ref"] for c in self.merged(top)["components"]]
            self.assertEqual(sorted(refs), sorted([API, IMPL, GUAVA, NETTY]))
            scoped = {
                c["bom-ref"]: c.get("scope")
                for c in self.merged(top)["components"]
            }
            self.assertEqual(scoped[NETTY], "required", "not a module")
            self.assertIn("archived/old/target/bom.json", verdict.log)
            self.assertNotIn("Merged archived", verdict.log)

    def test_skips_a_bom_a_nested_repository_tracks(self) -> None:
        """A BOM committed in a submodule is not the build's output."""
        with tempfile.TemporaryDirectory() as scratch:
            top = Path(scratch)
            reactor(top)
            place(top, "lib/old", module_bom(NETTY, [], {NETTY: []}))
            for repo in (top, top / "lib"):
                subprocess.run(
                    ["git", "init", "-q", str(repo)], check=True, timeout=30
                )
            subprocess.run(
                ["git", "-C", str(top / "lib"), "add", "old"],
                check=True,
                timeout=30,
            )

            verdict = self.merge(top)

            self.assert_passes(verdict, "a submodule's tracked BOM")
            self.assertIn("lib/old/target/bom.json", verdict.log)
            self.assertNotIn("Merged lib", verdict.log)

    def test_an_attached_artifact_is_its_module(self) -> None:
        """A sibling's dependency on api's test-jar names api itself."""
        with tempfile.TemporaryDirectory() as scratch:
            top = Path(scratch)
            tests = API.replace("?type=jar", "?classifier=tests&type=jar")
            place(top, "api", module_bom(API, [library(GUAVA)], {}))
            place(
                top,
                "impl",
                module_bom(
                    IMPL,
                    [library(tests), library(GUAVA)],
                    {IMPL: [tests], tests: [GUAVA], GUAVA: []},
                ),
            )

            verdict = self.merge(top)

            self.assert_passes(verdict, "a test-jar of a reactor module")
            document = self.merged(top)
            refs = [c["bom-ref"] for c in document["components"]]
            self.assertEqual(sorted(refs), sorted([API, IMPL, GUAVA]))
            edges = {
                d["ref"]: d["dependsOn"] for d in document["dependencies"]
            }
            self.assertEqual(edges[IMPL], [API])
            self.assertEqual(edges[API], [GUAVA])

    def test_fails_on_a_module_without_a_name(self) -> None:
        """A module BOM must name itself by a nonempty bom-ref."""
        for ref in (None, "", 7):
            with self.subTest(ref=ref), tempfile.TemporaryDirectory() as s:
                top = Path(s)
                bom = module_bom(API, [], {API: []})
                component = bom["metadata"]["component"]
                if ref is None:
                    del component["bom-ref"]
                else:
                    component["bom-ref"] = ref
                place(top, "api", bom)

                verdict = self.merge(top)

                self.assert_fails(verdict, f"bom-ref {ref!r}")
                self.assertFalse((top / "sbom-cyclonedx.json").exists())

    def test_ignores_boms_outside_the_modules(self) -> None:
        """A BOM in a target tree or beside no pom.xml is not a module."""
        with tempfile.TemporaryDirectory() as scratch:
            top = Path(scratch)
            reactor(top)
            bogus = json.dumps({"bomFormat": "bogus"})
            place(top, "impl/target/it/sample", None)
            nested = top / "impl/target/it/sample/target"
            nested.mkdir()
            (nested / "bom.json").write_text(bogus, encoding="utf-8")
            stray = top / "docs/target"
            stray.mkdir(parents=True)
            (stray / "bom.json").write_text(bogus, encoding="utf-8")

            verdict = self.merge(top)

            self.assert_passes(verdict, "stray BOMs are skipped")
            self.assertNotIn("sample", verdict.log)
            self.assertNotIn("docs", verdict.log)

    def test_takes_modules_beside_the_path_prefix(self) -> None:
        """A module the reactor names outside path_prefix is merged."""
        with tempfile.TemporaryDirectory() as scratch:
            top = Path(scratch)
            place(top, "reactor", module_bom(API, [], {API: []}))
            place(top, "outside", module_bom(IMPL, [], {IMPL: [API]}))

            verdict = self.merge(top)

            self.assert_passes(verdict, "a sibling of path_prefix")
            refs = [c["bom-ref"] for c in self.merged(top)["components"]]
            self.assertEqual(sorted(refs), sorted([API, IMPL]))

    def test_names_the_repository_it_scans(self) -> None:
        """The root names the repository the lane checks out."""
        step = step_of(job_of(load_workflow(MAVEN), "build"), MERGE_STEP)
        self.assertEqual(
            text(section(step, "env").get("REPOSITORY")),
            "${{ inputs.repository || github.repository }}",
        )

    def test_fails_without_a_module_bom(self) -> None:
        """A build that wrote no module BOM leaves nothing to scan."""
        with tempfile.TemporaryDirectory() as scratch:
            top = Path(scratch)
            place(top, ".", None)

            verdict = self.merge(top)

            self.assert_fails(verdict, "no module BOM")
            self.assertIn("::error::", verdict.log)
            self.assertFalse((top / "sbom-cyclonedx.json").exists())

    def test_fails_on_mixed_schemas(self) -> None:
        """Module BOMs of two specVersions do not merge into one."""
        with tempfile.TemporaryDirectory() as scratch:
            top = Path(scratch)
            reactor(top)
            place(top, "old", module_bom(NETTY, [], {}, spec="1.4"))

            verdict = self.merge(top)

            self.assert_fails(verdict, "1.4 beside 1.6")

    def test_fails_without_a_schema_version(self) -> None:
        """A module BOM must name its specVersion as a string."""
        for spec in (None, "", 1.6):
            with self.subTest(spec=spec), tempfile.TemporaryDirectory() as s:
                top = Path(s)
                bom = module_bom(API, [], {API: []})
                if spec is None:
                    del bom["specVersion"]
                else:
                    bom["specVersion"] = spec
                place(top, "api", bom)

                verdict = self.merge(top)

                self.assert_fails(verdict, f"specVersion {spec!r}")
                self.assertFalse((top / "sbom-cyclonedx.json").exists())

    def test_fails_on_a_document_that_is_not_cyclonedx(self) -> None:
        """A module's target/bom.json that is not CycloneDX fails."""
        with tempfile.TemporaryDirectory() as scratch:
            top = Path(scratch)
            reactor(top)
            place(top, "odd", {"bomFormat": "SPDX"})

            verdict = self.merge(top)

            self.assert_fails(verdict, "a non-CycloneDX module BOM")


class SbomSourceWiring(ContractCase):
    """The input, its validation and the steps it chooses between."""

    def validate(self, value: str) -> Verdict:
        """Run the extracted sbom_source validation with ``value``."""
        script = run_of(load_workflow(MAVEN), VALIDATE_JOB, SOURCE_VALIDATE)
        return run_script(script, {"SBOM_SOURCE": value})

    def condition(self, name: str) -> str:
        """Return the build step ``name``'s if: expression."""
        build = job_of(load_workflow(MAVEN), "build")
        return text(step_of(build, name).get("if"))

    def test_defaults_to_generate(self) -> None:
        """Without sbom_source the lane generates its SBOM as before."""
        workflow = load_workflow(MAVEN)
        inputs = section(
            section(section(workflow, "on"), "workflow_call"), "inputs"
        )
        default = section(inputs, "sbom_source").get("default")
        self.assertEqual(text(default), "generate")

    def test_validation_takes_the_two_sources_alone(self) -> None:
        """'generate' and 'build' pass; any other value fails."""
        for value in ("generate", "build"):
            self.assert_passes(self.validate(value), f"sbom_source '{value}'")
        for value in ("", "Build", "both", "build\n::warning::x"):
            self.assert_fails(self.validate(value), f"sbom_source {value!r}")

    def test_each_source_runs_its_own_steps(self) -> None:
        """Settings run under 'generate'; the merge under 'build' alone."""
        settings = self.condition(SETTINGS_STEP)
        self.assertIn("inputs.sbom_source == 'generate'", settings)
        merge = self.condition(MERGE_STEP)
        self.assertIn("inputs.sbom_source == 'build'", merge)
        self.assertIn("inputs.sbom_enabled", merge)
        self.assertIn("steps.build.outcome == 'success'", merge)

    def test_the_upload_takes_either_sbom(self) -> None:
        """The upload runs after a generated or a merged SBOM."""
        upload = self.condition(UPLOAD_STEP)
        self.assertIn("steps.sbom.outcome == 'success'", upload)
        self.assertIn("steps.sbom-merge.outcome == 'success'", upload)

    def test_the_merge_uploads_its_json_alone(self) -> None:
        """Under 'build' no stale sbom-cyclonedx.xml joins the upload."""
        build = job_of(load_workflow(MAVEN), "build")
        path = text(section(step_of(build, UPLOAD_STEP), "with").get("path"))
        self.assertEqual(
            path,
            "${{ inputs.sbom_source == 'build' && 'sbom-cyclonedx.json'"
            " || 'sbom-cyclonedx.*' }}",
        )


if __name__ == "__main__":
    unittest.main()
