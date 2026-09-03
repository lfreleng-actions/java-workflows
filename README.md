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

| Workflow                                           | Toolchain | Purpose                          | Caller trigger       |
| -------------------------------------------------- | --------- | -------------------------------- | -------------------- |
| `.github/workflows/maven-build-test.yaml`          | Maven     | Build, test, SBOM and Grype scan | Pull request         |
| `.github/workflows/gradle-build-test.yaml`         | Gradle    | Build, test, SBOM and Grype scan | Pull request         |

<!-- markdownlint-enable MD013 -->

These are `workflow_call` reusable workflows; they carry no trigger of
their own. "Caller trigger" is the event on which the shipped
`examples/` callers invoke them (pull request for the verify lane).

## Verify lane

The `maven-build-test.yaml` and `gradle-build-test.yaml` workflows are
complete. A `repository-metadata` job runs in parallel as an
informational step that does not gate the build. After `build`, the test
and SBOM/Grype branches run in parallel (jobs in `{ }` run concurrently;
`->` denotes sequence):

```text
build -> { tests | sbom -> grype }
```

The `build` job detects the project's Java version through
`build-metadata-action`, runs the build with `maven-build-action` or
`gradle-build-action`, gathers the JUnit XML the build emits, and uploads
it as an artefact. The `tests` job renders that XML through
`junit-test-report-action` into the job summary (it does not create a
check-run) and runs even when the build fails, so test failures
still surface a report. The `sbom` job generates a real CycloneDX SBOM
with `sbom-action` (syft static analysis of the checked-out tree) and
feeds the JSON document to `grype` under the `grype_fail_on` gate.

The generic template's standalone `audit` job does not appear here: on
the JVM, dependency-risk auditing is the SBOM/Grype chain plus the
separate Sonatype CLM lane, and the build tool (`surefire`/`failsafe` or
the Gradle `test` task) runs the tests as part of its own lifecycle.

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
exercises the Maven and Gradle verify workflows through their local
paths, so it validates the current branch. Both self-test jobs run on
every pull request. The Maven lane builds the dedicated
`test-maven-project` fixture under `block` egress; the Gradle lane
still builds a pinned upstream project under `audit` egress because no
`test-gradle-project` fixture exists yet (issue #50). See
[`docs/BRIEF.md`](docs/BRIEF.md) for detail.

## Design

Read [`docs/BRIEF.md`](docs/BRIEF.md) for the design decisions: the
Maven/Gradle split, the verify-lane wiring, the removed audit job, the
planned merge/release lanes, and the action-pinning policy.

[pre-commit.ci results page]: https://results.pre-commit.ci/latest/github/lfreleng-actions/java-workflows/main
[pre-commit.ci status badge]: https://results.pre-commit.ci/badge/github/lfreleng-actions/java-workflows/main.svg
