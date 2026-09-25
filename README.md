<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# ☕ Java Workflows

<!-- prettier-ignore-start -->
<!-- markdownlint-disable-next-line MD013 -->
[![Linux Foundation](https://img.shields.io/badge/Linux-Foundation-blue)](https://linuxfoundation.org/) [![Source Code](https://img.shields.io/badge/GitHub-100000?logo=github&logoColor=white&color=blue)](https://github.com/lfreleng-actions/java-workflows) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![pre-commit.ci status badge]][pre-commit.ci results page] [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/lfreleng-actions/java-workflows/badge)](https://scorecard.dev/viewer/?uri=github.com/lfreleng-actions/java-workflows)
<!-- prettier-ignore-end -->

Reusable GitHub Actions workflows that build, test and scan JVM projects
for the Linux Foundation. This repository covers both Maven and Gradle
projects, porting the Jenkins + global-jjb pipeline onto GitHub Actions.
This initial release provides the verify lane (build, test, SBOM and
Grype scan); [`docs/BRIEF.md`](docs/BRIEF.md) tracks the merge and release
lanes that follow later. The workflows keep the harden-runner
block posture, pinned action SHAs and dual Gerrit/GitHub trigger model of
`workflows-template`.

## Maven and Gradle families

GitHub resolves callable workflows from the flat `.github/workflows/`
directory, so the two toolchains split by filename prefix rather than by
subfolder:

<!-- markdownlint-disable MD013 -->

| Workflow                                           | Toolchain | Purpose                                | Caller trigger       |
| -------------------------------------------------- | --------- | -------------------------------------- | -------------------- |
| `.github/workflows/maven-build-test.yaml`          | Maven     | Build, test, SBOM/Grype scan and CBOM  | Pull request         |
| `.github/workflows/gradle-build-test.yaml`         | Gradle    | Build, test, SBOM/Grype scan and CBOM  | Pull request         |

<!-- markdownlint-enable MD013 -->

These are `workflow_call` reusable workflows; they carry no trigger of
their own. "Caller trigger" is the event on which the shipped
`examples/` callers invoke them (pull request for the verify lane).

## Verify lane

The `maven-build-test.yaml` and `gradle-build-test.yaml` workflows are
complete. A `repository-metadata` job runs in parallel as an
informational step that does not gate the build. After `build`, the
test, SBOM/Grype and CBOM branches run in parallel (jobs in `{ }` run
concurrently; `->` denotes sequence):

```text
build -> { tests | sbom -> grype | cbom }
```

The `build` job detects the project's Java version through
`build-metadata-action`, runs the build with `maven-build-action` or
`gradle-build-action`, gathers the JUnit XML the build emits, and uploads
it as an artefact. The `tests` job renders that XML through
`junit-test-report-action` into the job summary (it does not create a
check-run) and runs even when the build fails, so test failures
still surface a report. The `sbom` job generates a CycloneDX SBOM with
`sbom-action` and feeds the JSON document to `grype` under the
`grype_fail_on` gate. Both lanes use the action's `cyclonedx` backend,
which runs the CycloneDX Maven or Gradle plugin over the build tool's
resolved dependency graph. A static scan misses transitive dependencies
and BOM-managed versions in a `pom.xml`, and finds nothing in a Gradle
project without a `gradle.lockfile` (issues #47 and #48). A Gradle
wrapper older than the plugin supports (8.4, or 8.5 on Java 21) skips
the SBOM and Grype with a warning rather than failing the run.

The Maven `build` job passes `mvn_opts`, `mvn_pom_file` and `env_vars`
through to `maven-build-action`; each empty value keeps the action's
default. Java detection reads the selected POM's directory, and a POM
not named `pom.xml` requires `java_version`. The SBOM job resolves the
graph the build resolves, so it receives `mvn_opts` alongside
`mvn_profiles` and `mvn_params`, and exports the same `env_vars`. It
resolves `path_prefix/pom.xml`, and fails when `mvn_pom_file` names
another POM rather than describe a different project; set `path_prefix`
to that POM's directory instead. `env_vars` takes a JSON object of named
variables in place of `toJSON(vars)`. The export upper-cases each name
and skips one whose variable already holds a non-empty value; it
overwrites a variable that is present but empty. The SBOM job fails on
a name that is not an ASCII identifier, and on one that either Maven
step sets itself, such as `MAVEN_ARGS`. Both lanes take
`checkout_submodules` (default `false`), which checks out submodules in
every job that checks out the repository, including those a Gerrit
change adds.

The generic template's standalone `audit` job does not appear here: on
the JVM, dependency-risk auditing is the SBOM/Grype chain plus the
separate Sonatype CLM lane, and the build tool (`surefire`/`failsafe` or
the Gradle `test` task) runs the tests as part of its own lifecycle.

### CBOM (informational)

The `cbom` job runs `cbom-action` to produce a CycloneDX Cryptography
Bill of Materials: the algorithms, key sizes, modes, protocols and
certificates the code actually calls. An SBOM cannot express that, and
a CBOM is what post-quantum readiness assessments read.

**It never fails the workflow run.** The job sets `continue-on-error`
and pins the action's `fail_on_error` to `false`, so a scanner error, a
rejected input, or the job timeout all leave the run green. That covers
the whole leg on purpose — there is no `cbom_permit_fail` input,
because the report is advisory by contract rather than by configuration.
Set `cbom_enabled: false` to drop the job entirely.

It runs in parallel with the test and SBOM legs and gates nothing, so it
never delays another job. The run as a whole still waits for it, as it
does for every job, so a scan that outlasts every other branch extends
the total; `cbom_timeout_minutes` bounds that. In the self-test it takes
30–40 seconds, well inside the build. `needs: build` orders it
after the build; it does its own checkout and reads no build output.

One accuracy caveat follows from that. The scanner resolves Java symbols
from compiled classes and dependency jars where it finds them, and this
job scans a tree it has not built, so it resolves fewer symbols than a
scan over a built reactor would. Read the asset count as a floor.

CBOM files upload as `cbom-files-maven` / `cbom-files-gradle` with 45-day
retention, matching the SBOM artefacts. The job writes reports under
`RUNNER_TEMP`, never the workspace, so a project that tracks its own
`cbom.json` keeps it. The scanner image is a digest pinned inside
`cbom-action`, so it moves when the action pin moves rather than
through a workflow input.

**Known limitation.** The CBOM's metadata block (repository URL, branch,
commit) comes from the workflow run's own context, so it names the
*calling* repository and commit. Where `repository` or `ref` points at a
different tree, and on a Gerrit-sourced run where the checked-out change
is not the mirror commit, that metadata describes the caller rather than
the source scanned. This does not touch the cryptographic findings themselves.
Fixing it needs explicit metadata inputs on `cbom-action`.

<!-- markdownlint-disable MD013 -->

| Name                   | Type    | Default | Description                                                                              |
| ---------------------- | ------- | ------- | ---------------------------------------------------------------------------------------- |
| `cbom_enabled`         | boolean | `true`  | Generate a CBOM (set false to skip the job)                                              |
| `cbom_languages`       | string  | `''`    | Comma-separated languages to scan (`java`, `python`, `go`, `csharp`); empty auto-detects |
| `cbom_exclude`         | string  | `''`    | Comma-separated Java regex patterns to exclude; empty skips test sources                 |
| `cbom_module_cboms`    | boolean | `true`  | Emit a per-module CBOM alongside the consolidated one                                    |
| `cbom_empty_cboms`     | boolean | `true`  | Write CBOM files even when the scan finds no cryptographic assets                        |
| `cbom_timeout_minutes` | number  | `30`    | Timeout for the CBOM job, covering the container image pull as well as the scan          |

<!-- markdownlint-enable MD013 -->

## Usage

Copy a caller from [`examples/`](examples/) into your project's
`.github/workflows/` directory and replace the placeholder `uses:` SHA
with a pinned release. Each caller ships in two forms:

- `github.yaml` — a plain GitHub-native caller. The shipped verify
  callers are pull-request triggered.
- `gerrit.yaml` — a Gerrit-wrapped caller for projects where Gerrit is
  the source of truth, integrating with `gerrit_to_platform`
  voting/commenting.

```text
examples/
  maven/
    build-test/          { github.yaml, gerrit.yaml }
  gradle/
    build-test/          { github.yaml, gerrit.yaml }
```

Inputs are optional and default to the canonical behaviour; read the
`inputs:` block at the top of each workflow file for the documented list.

## Gerrit support

The reusable workflows are Gerrit-aware: a caller that sets the
`gerrit_refspec` input checks out the change with
`checkout-gerrit-change-action` in place of `actions/checkout`. Vote and
comment casting live in the `gerrit.yaml` caller examples (clear vote →
run → report vote for verify), never inside the reusable workflows.

## Testing

[`.github/workflows/testing.yaml`](.github/workflows/testing.yaml)
exercises the Maven and Gradle verify workflows by self-repository path
(`uses: $/.github/workflows/maven-build-test.yaml` and its Gradle
counterpart), which resolves this repository at the commit already
running, so it validates the current branch. Both self-test jobs run on
every pull request. The Maven lane builds the dedicated
`test-maven-project` fixture under `block` egress; the Gradle lane
still builds a pinned upstream project under `audit` egress because no
`test-gradle-project` fixture exists yet (issue #50). A
`pass-through-check` job proves the Maven lane's `mvn_opts` and
`env_vars` reach both the build and the SBOM, and a `pom-check` job
proves a second Maven call builds the `mvn_pom_file` it names. A
`wiring-check` job runs `.github/scripts/wiring-check.sh` to test the
guard steps and the submodule wiring the fixtures cannot exercise. See
[`docs/BRIEF.md`](docs/BRIEF.md) for detail.

## Design

Read [`docs/BRIEF.md`](docs/BRIEF.md) for the design decisions: the
Maven/Gradle split, the verify-lane wiring, the removed audit job, the
planned merge/release lanes, and the action-pinning policy.

[pre-commit.ci results page]: https://results.pre-commit.ci/latest/github/lfreleng-actions/java-workflows/main
[pre-commit.ci status badge]: https://results.pre-commit.ci/badge/github/lfreleng-actions/java-workflows/main.svg
