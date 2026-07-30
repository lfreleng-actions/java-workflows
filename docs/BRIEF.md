<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

<!-- markdownlint-disable MD013 -->

# Design Brief: Java Workflows

This document records the design decisions behind `java-workflows`: the
reusable GitHub Actions workflows that build, test, scan and release JVM
projects in the `lfreleng-actions` organisation. It is the
language-specific instantiation of `workflows-template` for Java, and it
targets both Maven and Gradle projects.

The immediate driver is the ONAP `cps` migration off Jenkins + global-jjb
(Java 21, Maven 3.9 multi-module, plus some Gradle) onto GitHub Actions
reusable workflows. The patterns generalise to every LF Java project.

## Goal

Give Java projects a drop-in set of reusable workflows that reproduce the
Jenkins/global-jjb verify, merge and release lanes on GitHub Actions,
while inheriting the template's security posture (harden-runner block
mode, pinned SHAs, SBOM/Grype chain) and dual Gerrit/GitHub trigger model
by default.

## Maven and Gradle: one repository, two lanes

GitHub resolves reusable workflows only from the flat `.github/workflows/`
directory; subdirectories are not permitted for callable workflows. The
Maven and Gradle families are therefore delineated by **filename prefix**,
not by folder:

| File                     | Family | Lane        |
| ------------------------ | ------ | ----------- |
| `maven-build-test.yaml`  | Maven  | Verify (PR) |
| `gradle-build-test.yaml` | Gradle | Verify (PR) |

This initial repository ships only the verify lane. The planned merge and
release lanes will follow the same prefix convention when added
(`maven-merge.yaml`, `maven-build-test-release.yaml`, and their Gradle
counterparts); see [Planned: merge and release lanes](#planned-merge-and-release-lanes).

Only `examples/` and `docs/` use real subfolders (`examples/maven/…`,
`examples/gradle/…`). Gradle is a first-class parallel track, not an
afterthought: there are fewer Gradle projects than Maven ones, but the
same verify/merge/release shape applies, so the Gradle workflows mirror
their Maven counterparts step-for-step and differ only in the toolchain
actions and their inputs.

## Verify lane (wired)

Both `maven-build-test.yaml` and `gradle-build-test.yaml` are fully
wired. The job graph is:

```text
gerrit-validate ─┬─ repository-metadata (informational)
                 └─ build ─┬─ tests
                           └─ sbom ─ grype
```

`build` job (Maven):

1. `build-metadata-action` (id `metadata`) — detects the project's Java
   version and version/release metadata; writes to the step summary.
2. `maven-build-action` (id `build`) — runs `setup-java` + `setup-maven`
   itself, then the configured Maven phases (default `clean install`).
   The Java version resolves as
   `inputs.java_version || metadata.java_version || '21'` so an explicit
   caller value wins, project detection is next, and 21 is the floor.
3. A "Collect JUnit reports" step (id `reports`, `if: always()`) finds
   `*/target/*-reports/*.xml`, copies them under `junit-reports/`, and
   sets `found`.
4. When reports exist, they upload as the `maven-junit-reports` artefact.
5. When `upload_build_artifacts` is set, a "Collect build artefacts"
   step stages the packaged output and uploads it.

Build artefact publication is **opt-in**. The packaged output is large
and most verify lanes never read it back, so uploading it unconditionally
would charge storage to every consumer in order to serve a minority. The
cases that want it are real, though — publish and stage lanes, container
builds, CSIT, and a human pulling a jar out of a failed run — so the
workflow makes it a switch rather than omitting it.

Two shapes can come out of a Maven build, and they are not
interchangeable. A `deploy` phase writes a repository layout to `m2repo`
(`groupId/artifactId/version/...`), which is what Nexus staging and
`nexus-publish-action` consume; any other phase leaves packaged output
scattered through the reactor's `target/` directories. The collect step
prefers the former when it exists and records which it took in the
artefact name (`maven-build-artifacts-m2repo` or
`maven-build-artifacts-reactor`), so a consumer knows what it has
without inspecting the contents. Note the lane's default `mvn_phases` is
`clean install`, which produces the reactor shape; `m2repo` appears only
when a caller asks for `deploy`. The build job also surfaces
`m2repo_exists`, `m2repo_path` and `artifact_count` as job outputs.

Gradle has no `m2repo` equivalent in a plain build, so its lane collects
one shape — each module's `build/libs` output — and names the artefact
`gradle-build-artifacts`.

A global `settings.xml` (which commonly carries Nexus server credentials)
is never accepted as a plain input: the workflow declares a
`maven_global_settings` `workflow_call` secret and forwards it to
`maven-build-action`'s `global-settings`, keeping the value masked in logs
and the run UI. Callers typically synthesise it with
`maven-xml-settings-action` and omit the secret entirely when no global
settings are needed.

`tests` job downloads that artefact and runs `junit-test-report-action`
against `junit-reports/**/*.xml` with
`fail-on-failure: ${{ !inputs.test_permit_fail }}`. The action writes a
results table to the job summary; it does not create a check-run. Its
own artefact upload is disabled (`artifact-upload: 'false'`) because the
build job already publishes the XML as `maven-junit-reports`. The job
runs whenever the build was not skipped
(`needs.build.result != 'skipped'`), including a failed build: Maven and
Gradle run the tests inside the build, so a test failure fails the build
job, and gating the report on build success would hide exactly the
failures the report exists to show.

Because tests run in the build, `test_permit_fail` cannot soft-fail by
itself. The Maven workflow therefore adds
`-Dmaven.test.failure.ignore=true` so the build completes and the report
gate decides the verdict. Gradle has no equivalent CLI flag, so there
the input governs only the report gate; a project must set
`test.ignoreFailures` to tolerate failures at build level. The input
descriptions state this per toolchain.

The Gradle build job is identical in shape: `gradle-build-action` with
`java-version` / `gradle-version` / `build-arguments` (default `build`),
report discovery on `*/build/test-results/*/*.xml`, and the
`gradle-junit-reports` artefact. `gradle-build-action` uploads test
reports itself by default, so the workflow sets `artifact-upload: false`
and manages the artefact under a stable name for the tests job.

`sbom` generates a real CycloneDX document with `sbom-action` (a syft
backend performing static analysis of the checked-out tree) and feeds the
JSON output to `grype`, honouring `grype_fail_on`, `grype_permit_fail` and
the `NO_BLOCK_AUDIT_FAIL` repository variable (carried verbatim from the
template). With the action's defaults it writes `sbom-cyclonedx.json` and
`sbom-cyclonedx.xml` at the workspace root — the JSON document is the
Grype job's scan contract — and reports the component count to the job
summary. Because the SBOM job does its own checkout and does not depend on
the build's artefacts, it still produces a dependency-scan signal when the
build fails.

## No dedicated java-audit-action or java-test-action

Two lanes present in the generic template do not appear as standalone
Java jobs, by deliberate decision:

- **No `audit` job.** For the JVM, dependency-risk auditing is the
  SBOM + Grype chain (already present) plus the separate Sonatype CLM
  lane; there is no separate "audit" step to run. The template's generic
  `audit` job and its `audit_permit_fail` input were removed from the
  Java verify workflows.
- **No dedicated test action.** Maven (`surefire`/`failsafe`) and Gradle
  (`test`) run the tests as part of the build lifecycle. The workflow's
  job is to *surface* results, which `junit-test-report-action` does by
  rendering the JUnit XML the build already produced. A separate
  test-runner action would duplicate the build tool's own contract.

## Planned: merge and release lanes

The merge (`*-merge.yaml`) and release (`*-build-test-release.yaml`) lanes
are **not part of this initial repository**. They are intentionally
sequenced **last**, because the stage/release lane depends on design
decisions that are not yet settled:

- **Signing**: Sigul (LF's traditional signing bridge) versus Sigstore
  keyless/OIDC. Some Gerrit-mirrored or air-gapped consumers cannot reach
  public Sigstore infrastructure.
- **Nexus2 staging semantics**: the ONAP flow stages to a Sonatype Nexus2
  open/close/promote lifecycle; the reusable equivalent (staging profile,
  auto-release gating) needs modelling.
- **Model B data bus**: the Jenkins `releases/*.yaml` +
  `log_dir` convention needs a GitHub-native replacement for carrying
  release coordinates between the merge trigger and the publish step.

These lanes are omitted rather than committed as placeholders: the initial
repository ships only complete, functional workflows. They will be added
under the filename-prefix convention above once the design decisions are
resolved.

## Supporting building-block actions

The verify lane composes actions from sibling `lfreleng-actions` repos.
The Java-specific enhancements landed (or are in review) as separate PRs
before this repository wired them together:

| Action                      | Role in the lane                               |
| --------------------------- | ---------------------------------------------- |
| `build-metadata-action`     | Java version + release metadata detection      |
| `maven-build-action`        | Maven setup + lifecycle build                  |
| `gradle-build-action`       | Gradle setup + build (brought to Maven parity) |
| `junit-test-report-action`  | JUnit XML rendering + check                    |
| `sbom-action`               | CycloneDX SBOM generation (syft backend)       |
| `maven-xml-settings-action` | Nexus `settings.xml` synthesis (merge lane)    |

The `java-version` input naming was normalised across every build action
before the workflows depended on it, since renaming a consumed input
after the fact would be a breaking change.

## Action pin policy

zizmor's auditor persona rejects `@main`/branch refs (`unpinned-uses`), so
every `uses:` ref is pinned to a full commit SHA with a `# vX.Y.Z` comment
naming the release it targets, matching the template convention. All
building-block actions the verify lane composes are pinned to published
release tags:

| Action                     | Release |
| -------------------------- | ------- |
| `build-metadata-action`    | v0.7.0  |
| `maven-build-action`       | v0.3.0  |
| `gradle-build-action`      | v0.5.0  |
| `junit-test-report-action` | v0.0.1  |
| `sbom-action`              | v0.0.1  |

## Self-test approach

`testing.yaml` calls the Maven and Gradle verify workflows by **local
path**, so it always validates the current branch. Both self-test jobs
are gated to `workflow_dispatch` only (skipped on pull requests, keeping
PR CI green) while one prerequisite is pending:

1. Dedicated lightweight fixtures (`test-maven-project` /
   `test-gradle-project`) exist; the placeholders build large upstream
   projects and suit a manual run only.

The two earlier prerequisites are satisfied: every building-block action
is pinned to a published release, and the toolchain egress (Maven
Central, Gradle distribution, Temurin, and the syft and grype tool
downloads) is in the central harden-runner allow-list as of `.github`
v0.7.0. The placeholder jobs still run in audit because a large upstream
project reaches endpoints beyond that toolchain set; a dedicated fixture
with a known egress footprint can switch them to block mode.

The planned merge and release lanes are out of scope for the self-test
until they are added: they need a merged-commit or signed semver tag-push
context that is neither available nor safe on a pull request.

## Conventions inherited from the template

- Workflow `name:` prefixed `[R]`.
- All `workflow_call` inputs `required: false`, lowercase snake_case
  (UPPERCASE `GERRIT_*` names reserved for dispatch inputs on callers).
- Top-level `permissions: {}`; minimal per-job grants with explanatory
  comments; `timeout-minutes` on every job. The build, test-report and
  audit jobs take their timeout from an input
  (`build_timeout_minutes` 45, `tests_timeout_minutes` 30,
  `sbom_timeout_minutes` 30, `grype_timeout_minutes` 30) because their
  duration scales with the project; the validation and metadata jobs do
  fixed work and keep literal values. The defaults assume a large
  multi-module reactor on a busy shared runner, where dependency
  resolution, container image pulls and vulnerability database
  downloads all run slower than they do locally. A timeout only bounds
  a hung job, so erring high costs nothing; the previous flat 10
  minutes silently truncated a real ONAP build mid-reactor, and a
  caller could not raise it because a reusable workflow's job timeout
  is not overridable from outside.
- Every `uses:` pinned to a full commit SHA; `persist-credentials: false`
  on every checkout.
- One harden-runner step per job with the egress policy computed
  (block-mode allow-list load, then harden-runner); fail-secure (anything
  other than `audit` means block). The policy is computed rather than
  chosen between two conditional steps because harden-runner declares a
  `pre` entry point and no `pre-if`, so its pre-phase runs regardless of
  a step-level `if:`. Two steps would both engage the agent, the first
  would win, and audit mode would be silently unreachable. The central
  allow-list is pinned in the `harden_runner_allowlist` default.
  The build job additionally honours `build_permit_egress_traffic`
  (boolean, default `false`): when true it runs harden-runner in audit
  for the build lane only — for dependency fetches from CDNs impractical
  to enumerate in the allow-list — while every other job stays governed by
  `harden_runner_egress`. This is a first, build-scoped hook; per-job
  egress control can be generalised later if further lanes need it.
- Never interpolate `${{ }}` into `run:` blocks; env-mediate dynamic
  values (zizmor template-injection). `with:`-block interpolation is
  safe.
- Dual checkout switch on `gerrit_refspec`
  (`checkout-gerrit-change-action` when set, `actions/checkout`
  otherwise).

## Follow-ups

1. Create `test-maven-project` / `test-gradle-project` fixtures and point
   `testing.yaml` at them.
2. Design and implement the merge/release lanes (signing, Nexus2 staging,
   Model B data bus).
3. Wire the ONAP `cps` Gerrit verify/merge workflows onto these reusable
   workflows.
