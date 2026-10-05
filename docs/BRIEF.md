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

This initial repository ships only the verify lane. The merge and
release lanes will follow the same prefix convention when added
(`maven-merge.yaml`, `maven-stage.yaml`, `maven-build-test-release.yaml`,
and their Gradle counterparts); see [Merge lane](#merge-lane-designed)
and [Release lane](#release-lane-planned).

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
                 └─ build ─ grype
```

One job owns the built tree: every step that reads it runs inside
`build`, so nothing is checked out, resolved or built twice. Only
`grype`, which reads nothing but the SBOM document, runs downstream.

`build` job (Maven):

1. `build-metadata-action` (id `metadata`) — detects the project's Java
   version and version/release metadata; writes to the step summary.
2. `maven-build-action` (id `build`) — runs `setup-java` + `setup-maven`
   itself, then the configured Maven phases (default `clean install`).
   The Java version resolves as
   `inputs.java_version || metadata.java_version || '21'` so an explicit
   caller value wins, project detection is next, and 21 is the floor.
   `mvn_opts`, `mvn_pom_file` and `env_vars` pass through to the
   action's `mvn-opts`, `mvn-pom-file` and `env-vars`. A composite
   action applies a default only when an input is absent, never when it
   arrives empty, so each empty value falls back to the action's own
   default: the workflow restates v0.4.3's `mvn-opts` default (the
   `/tmp/r` local repository and quiet transfer logging), `pom.xml`,
   and `{}`. A non-empty `mvn_opts` replaces that default rather than
   adding to it, as it does on the action. `env_vars` takes a JSON
   object of named variables and replaces the legacy `toJSON(vars)`
   pattern, which exported every repository variable into the build.
   `build-metadata-action` reads the `pom.xml` in the directory it is
   given, so the build points it at the selected POM's directory. It
   cannot read a POM under another name and would report on whichever
   `pom.xml` sits beside it, so such a POM requires `java_version`, and
   the build fails early without one.
3. A "Collect JUnit reports" step (id `reports`, `if: always()`) finds
   `*/target/*-reports/*.xml`, copies them under `junit-reports/`, and
   sets `found`.
4. When reports exist, they upload as the `maven-junit-reports` artefact
   and `junit-test-report-action` renders them into the job summary.
5. When `upload_build_artifacts` is set, a "Collect build artefacts"
   step stages the packaged output and uploads it.
6. `sbom-action` generates the SBOM and uploads it as `sbom-files-maven`.
7. `cbom-action` generates the CBOM and uploads it as `cbom-files-maven`.

Steps 3 onwards run whatever the build's outcome (`!cancelled()` or
`always()`), so a failed build still reports its tests and produces its
SBOM and CBOM. Each folded step keeps its own timeout input
(`tests_timeout_minutes`, `sbom_timeout_minutes`,
`cbom_timeout_minutes`) as a step-level `timeout-minutes`, all within
`build_timeout_minutes`, which bounds the whole job.

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

The test summary runs `junit-test-report-action` against
`junit-reports/**/*.xml` with
`fail-on-failure: ${{ !inputs.test_permit_fail }}`. The action writes a
results table to the job summary; it does not create a check-run. Its
own artefact upload is disabled (`artifact-upload: 'false'`) because the
build job already publishes the XML as `maven-junit-reports`. It runs
after a failed build step too: Maven and Gradle run the tests inside
the build, so a test failure fails the build step, and gating the
report on build success would hide exactly the failures the report
exists to show.

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
and manages the artefact under a stable name.

The SBOM steps generate a real CycloneDX document with `sbom-action`
and upload it for `grype`, which honours `grype_fail_on`,
`grype_permit_fail` and the `NO_BLOCK_AUDIT_FAIL` repository variable
(carried verbatim from the template). With the action's defaults it
writes `sbom-cyclonedx.json` and `sbom-cyclonedx.xml` at the workspace
root — the JSON document is the Grype job's scan contract — and reports
the component count to the job summary. The build job exposes
`sbom_uploaded`, and `grype` runs only when it is `true`.

Both lanes use `sbom-action`'s `cyclonedx` backend, because a Java
build file is an input to dependency resolution rather than a product
of it. Static analysis of `pom.xml` sees only the dependencies written
there, misses every transitive one, and reports versions managed by a
parent or an imported BOM as `UNKNOWN`, which Grype cannot match
(issue #47). Gradle fares worse: static analysis reads only a
`gradle.lockfile`, and dependency locking is opt-in, so most projects
yield nothing at all (issue #48). The backend drives each build tool's
own resolver instead: `cyclonedx-maven-plugin`'s `makeAggregateBom` for
Maven, and for Gradle an init script that applies
`cyclonedx-gradle-plugin` and runs `cyclonedxBom` on the root project,
covering every subproject without editing the consumer's build files.
Neither compiles, so the SBOM still generates when the build fails on a
test, and fails only when resolution fails, where there is no graph to
describe. Both read the dependencies the build has just resolved:
the Maven lane passes `-Dmaven.repo.local=/tmp/r`, the local repository
`maven-build-action`'s default `mvn-opts` populate, and the Gradle lane
shares the build's Gradle user home. Test-scoped dependencies (Gradle test configurations) stay
out: the SBOM describes the shipped artefact. Each lane names its build
tool through `dependency_manager` rather than leaving the action to
infer it.

`cyclonedx-gradle-plugin` needs Gradle 8.4 or newer, rising with the
JDK (8.5 on the default Java 21). Below that floor the backend skips
and writes no document. The SBOM runs the same Gradle the build does.
By default that is the project's wrapper, whose version
`build-metadata-action` reports. When a caller pins `gradle_version`,
the build runs a provisioned Gradle instead, already on `PATH`. Since
`sbom-action` prefers an executable `gradlew`, the lane clears the
wrapper's execute bit for the SBOM step and restores it on `always()`,
leaving the file itself untouched. Either way the lane passes that
version to the floor check, which then settles before anything
downloads. A skip raises a warning and a job summary line, uploads
nothing and skips Grype, rather than failing the upload on a missing
file and misattributing an old Gradle to a broken SBOM step.

The `cyclonedx` backend runs the build tool over the checkout. Maven
loads project extensions, and evaluating a Gradle build runs its build
scripts, so the checkout is executable input. The action's
`untrusted_checkout: auto` would skip on a fork pull request, losing the
SBOM, and cannot recognise a Gerrit change at all. The workflows set
`untrusted_checkout: 'false'` instead: the build step has already run
the same build over the same checkout with the same read-only token and
settings, so the SBOM step exposes nothing the build does not.

The SBOM resolves the graph the build resolves. It uses the same
Java version and, in the Maven lane, the `mvn_version` the build step
left on `PATH` (`sbom-action` runs whichever `mvn` it finds there). It
passes the same `mvn_profiles`, `mvn_opts`, `mvn_params` and
`maven_global_settings`, since each can add modules, repositories or
dependency versions. `mvn_opts` belongs in that list because
`maven-build-action` places `mvn-opts` on the `mvn` command line, not in
`MAVEN_OPTS`, where a `-D` or `-P` selects dependencies as surely as one
in `mvn_params`. A non-empty `mvn_opts` is forwarded verbatim, so any
`maven.repo.local` it sets applies to both steps. An empty one gives the
build the action's default, which places the local repository at
`/tmp/r`, so the SBOM step passes `-Dmaven.repo.local=/tmp/r` in its
place and reuses what the build downloaded rather than fetching the
graph again into `~/.m2`.

`env_vars` reaches resolution as well: a profile can activate on an
`env.*` property, a POM can read one into a dependency version, and
`MAVEN_OPTS` carries system properties into Maven (a `projectType` set
there retypes the SBOM's root component). The build step exports it
with `vars-to-env-action`, which writes `GITHUB_ENV`, so the SBOM step
later in the same job inherits the same values without exporting them
again. A name that either Maven step sets itself would still differ
between the two, because a step's own `env:` wins over `GITHUB_ENV`:
`sbom-action`'s generate step forces `MAVEN_ARGS` empty, and both steps
set their own inputs as variables. When `sbom_enabled` is set, the build
job fails before checkout on any of those names, on a name that is not
an ASCII identifier, and on a value that is not a JSON object. The ASCII
rule closes a bypass: the action upper-cases with JavaScript's
`toUpperCase()`, which maps some non-ASCII letters onto ASCII ones
(`maven_arg` followed by U+017F exports as `MAVEN_ARGS`), while the
guard's `ascii_upcase` leaves them. The name lists follow `sbom-action`
v0.2.0 and `maven-build-action` v0.4.3 and move with their pins.

`sbom-action` resolves `path_prefix/pom.xml` and rejects `-f`/`--file`
in `maven_args`, because an alternate POM would escape the directory it
validated, so `mvn_pom_file` cannot reach it. When `mvn_pom_file` names
any POM other than `pom.xml` and `sbom_enabled` is set, the build job
fails before checkout rather than describe a different project from the
one built under the same name; the caller sets `path_prefix` to the
POM's directory instead, or `sbom_enabled: false`. A warning would still
upload the wrong document for Grype to pass. The SBOM steps run on
`!cancelled()`, so they require both guards to have succeeded by name
rather than relying on the implicit `success()` gate. The Gradle lane
fails closed the same way on the project-selection options in
`build_arguments`, which forwards the property options (`-P`/`-D` and
their long forms) and leaves out tasks and other flags.
`maven-build-action` removes its own settings file when it finishes, so
the secret is written again to a private file under `RUNNER_TEMP`, only
when set, and removed on `always()`. One difference remains:
`maven-build-action` expands workspace variables such as
`${GITHUB_WORKSPACE}` in `mvn_opts` and `mvn_params`, and the SBOM path
passes them to Maven unexpanded.

The CBOM steps scan the same built tree, so `cbom-action` resolves
symbols against compiled classes rather than bare source. They cannot
fail the run: `fail_on_error` is pinned `false` and both steps set
`continue-on-error`. That cannot absorb the job timeout, so a budget
step clamps the scan's timeout to what remains of
`build_timeout_minutes` (from a timestamp taken after harden-runner),
less five minutes for the phases outside that window, and skips the
scan with a warning when nothing remains. When `cbom_enabled` is set,
the build job's harden-runner also allows `ghcr.io:443` and
`pkg-containers.githubusercontent.com:443` for the scanner image, so a
narrower `harden_runner_allowlist` does not cost the CBOM.

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

## Merge lane (designed)

`maven-merge.yaml` publishes Maven SNAPSHOTs when a change merges. The
design below is agreed; the workflow is not written yet, because the
building blocks it pins are still in review (see
[Merge-lane prerequisites](#merge-lane-prerequisites)). It replaces the OpenDaylight
`compose-maven-merge.yaml` from `lfit/releng-reusable-workflows`, keeping
the behaviour worth keeping and none of its code.

### Decisions

<!-- markdownlint-disable MD013 -->

| ID  | Question                     | Decision                                                                                 |
| --- | ---------------------------- | ---------------------------------------------------------------------------------------- |
| D-1 | Publish credential           | `credential-load-action`, as the node and docker lanes use; optional GitHub environment  |
| D-2 | What the lane builds         | The branch head, as the legacy lane and global-jjb do                                    |
| D-3 | SBOM, Grype and provenance   | SBOM and Grype for information only; signing and attestation on full releases alone      |
| D-4 | Reactor coordinates          | Maven's own `help:effective-pom`, inside `maven-snapshot-metadata-action`                |
| D-5 | Artifactory                  | Kept for later; no project needs it, so neither lane ships it initially                  |

<!-- markdownlint-enable MD013 -->

### Job graph

```text
gerrit-validate ─┬─ repository-metadata (informational)
                 └─ build ─┬─ publish-snapshot
                           └─ sbom ─ grype (informational)
```

The shape is build once, publish from the artefact, as the node and
docker merge lanes do: the job that runs the project's code never holds
the write credential, and the job that holds it never runs the code.

### Build job

1. Check out the branch head (D-2), with `persist-credentials: false`.
2. `build-metadata-action`, for the Java version, as in the verify lane.
3. Set up the JDK and Maven explicitly, with the versions the build
   resolves (`java_version`, `mvn_version`) and the same installers and
   pins `maven-build-action` uses. `fetch` runs Maven before
   `maven-build-action` provisions its own toolchain, and relying on
   the runner's defaults could make `help:effective-pom` fail, or read
   the reactor differently from the deploy, on a self-hosted runner or
   with a pinned Maven. `maven-build-action` then installs the same
   versions, so the toolchain does not change between the two.
4. `maven-snapshot-metadata-action` in `fetch` mode. It runs
   `help:effective-pom` once over the reactor, then seeds the published
   `maven-metadata.xml` for every module into the `m2repo`, so
   `maven-deploy-plugin` carries on from the published `buildNumber`.
5. `maven-build-action` with `mvn-phases: clean deploy`, deploying to its
   fixed `m2repo`. `run-jacoco` and `artifact-upload` are off: coverage
   belongs to the verify lane, and the workflow uploads the tree itself.
   The seeding relies on the action leaving an existing `m2repo` in
   place, a contract lfreleng-actions/maven-build-action#157 adds a test and
   documentation for. It also relies on the deploy landing there, which
   a caller can currently break: the action places `mvn-opts` and
   `mvn-params` after its own `-DaltDeploymentRepository`, and Maven
   honours the last one given, so a caller's own would redirect the
   deploy while `prune` and the upload still read `m2repo`, publishing
   only the seeded metadata. The action must refuse that override, or
   place its value last, before the lane passes caller arguments.
6. `maven-snapshot-metadata-action` in `prune` mode, removing metadata
   the deploy left unchanged, which would otherwise overwrite newer
   copies a sibling build published meanwhile.
7. Upload the pruned `m2repo` as the hand-off artefact, kept three days:
   enough to re-run a failed publish job without rebuilding, without
   carrying a whole reactor's output for the default 90.

`fetch` takes no credentials. OpenDaylight's `opendaylight.snapshot` and
ONAP's `snapshots` repositories both serve metadata anonymously (checked
against both servers), and passing even a read credential into this job
would expose it to the build. A project with a private snapshot
repository would need a scoped read credential added deliberately, with
that trade-off stated.

### Publish job

1. Download the `m2repo` artefact.
2. Load the Nexus password with `credential-load-action`, gated on the
   `CREDENTIAL_LOAD_GRANTS` variable and with `export_env: false`, so the
   secret stays a step output and never enters the job environment. The
   username comes from an input, falling back to the repository name, as
   in the node lane.
3. `nexus-publish-action` in `maven2_upload` mode, once per top-level
   group path from `fetch`'s `group_paths` output, so artefacts outside
   the root `groupId` publish too. The action retries transient failures,
   uploads `maven-metadata.xml` after everything it describes, and holds
   the metadata back when anything before it failed, so a partial publish
   never advertises a SNAPSHOT that is not there.
4. A step summary with the built commit, branch, group paths, metadata
   seeded and pruned, and files published and failed (gap analysis G-15).

An optional `publish_environment` input puts this job, and only this
job, in a GitHub environment, for projects that keep the credential
behind environment protection rules.

### What the lane does not do

- **Signing and attestation (D-3).** SNAPSHOTs are neither signed nor
  attested, as the node lane skips them for snapshots too; that belongs
  to the release lane.
- **Maven Central and Artifactory.** Central is a release target (G-10);
  Artifactory is deferred until a project needs it (D-5).
- **Concurrency.** The caller owns it; see below.

### Caller responsibilities

The caller keeps what depends on the project's own setup:

- **Triggers:** the `gerrit_to_platform` dispatch with its `GERRIT_*`
  inputs, and a daily scheduled rebuild, which the legacy lane runs at
  02:49 UTC, the retired Jenkins slot.
- **Replication:** wait until the merged `GERRIT_PATCHSET_REVISION` is
  reachable from the mirrored `GERRIT_BRANCH` before calling the lane.
  Gerrit dispatches on merge, possibly before its replication to the
  GitHub mirror lands, and the lane builds the branch head (D-2); without
  the wait it could publish the previous head's SNAPSHOT while voting on
  the new change. Poll for the revision rather than sleep a fixed time,
  as the legacy caller's 10-second wait does.
- **Votes:** clear before building and vote on the result, both skipped
  on scheduled runs, with `gerrit-review-action`.
- **Secrets by name:** `OP_SERVICE_ACCOUNT_TOKEN` and
  `VAULT_MAPPING_JSON`, since `secrets: inherit` does not cross
  organisations.
- **Concurrency, keyed on the repository:**

  ```yaml
  concurrency:
    group: maven-merge-${{ github.repository }}
    cancel-in-progress: false
    queue: max
  ```

  This departs from the legacy caller, which keys on the branch. Every
  version of an artifact shares one artifact-level `maven-metadata.xml`,
  so lanes for two branches, at `1.1.0-SNAPSHOT` and `1.0.1-SNAPSHOT`
  say, would each add their version and the later publish would drop
  the other's. A running lane is never cancelled, since one stopped
  between fetch and publish would leave the numbering behind.
  `cancel-in-progress: false` protects the running lane alone: by
  default a group holds one pending run, and a newer one cancels it.
  Within one branch that loses nothing, as the newer run builds a later
  head, but a group spanning branches would drop another branch's
  publish and its Gerrit vote. `queue: max` keeps up to 100 pending
  runs, in order, and GitHub rejects it beside `cancel-in-progress:
  true`.
  A concurrency group covers one GitHub repository and no further;
  publishers in different repositories need disjoint group paths.

### Self-test

The lane runs on merges, but most of it can run on a pull request. The
self-test will build `test-maven-project` with `clean deploy`, run
`fetch` and `prune` against a mock Nexus serving published metadata,
and publish with `nexus-publish-action`'s `dry_run`, asserting that the
`buildNumber` carries on and untouched metadata stays unpublished.
`maven-snapshot-metadata-action` already runs that sequence on a real
Maven deploy, on Maven 3.9 and Maven 4, so the self-test proves the
wiring rather than the mechanism.

### Merge-lane prerequisites

<!-- markdownlint-disable MD013 -->

| Building block                   | Needed for                                         | State                                                                                               |
| -------------------------------- | -------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `maven-snapshot-metadata-action` | `fetch` and `prune`                                | First release in review                                                                             |
| `nexus-publish-action`           | Retries, metadata last and held back; `dry_run`    | In review (lfreleng-actions/nexus-publish-action#171 and lfreleng-actions/nexus-publish-action#172) |
| `maven-build-action`             | The tested `m2repo` contract                       | In review (lfreleng-actions/maven-build-action#157)                                                 |
| `maven-build-action`             | An `m2repo` deploy path callers cannot override    | To do                                                                                               |
| `java-workflows`                 | `mvn_opts`, `mvn_pom_file`, `env_vars`, submodules | In review (#68)                                                                                     |
| `maven-xml-settings-action`      | Mirror-only settings without credentials           | In review (lfreleng-actions/maven-xml-settings-action#32)                                           |

<!-- markdownlint-enable MD013 -->

## Release lane (planned)

The release lane reproduces the stage-then-release flow both target
projects run on Jenkins today. ONAP `cps` (`ci-management`) and
OpenDaylight `infrautils` (`releng/builder`, through the
`odl-maven-jobs-jdk21` group) both use global-jjb's
`gerrit-maven-stage` with `sign-artifacts: true`, and both release by
merging a release file. One lane shape serves both.

### Two workflows

<!-- markdownlint-disable MD013 -->

| Workflow                        | Trigger              | Does                                                         |
| ------------------------------- | -------------------- | ------------------------------------------------------------ |
| `maven-stage.yaml`              | Dispatch or schedule | Build a release candidate, sign it, stage it in Nexus        |
| `maven-build-test-release.yaml` | A release file merge | Validate the file, promote the named staged build, tag it    |

<!-- markdownlint-enable MD013 -->

Staging and releasing stay apart, as on Jenkins: a candidate is staged
and tested first, and a release file later promotes one exact staging
repository, identified by the file's `log_dir`. Rebuilding at release
time would publish something nobody tested.

The release commit travels with the staged build, and two commits are
involved. Jenkins' stage job (global-jjb `maven-patch-release.sh`)
first records the **source** commit, the revision it checked out, in
`taglist.log`. That is not always the branch head: `gerrit-maven-stage`
is comment-triggered and checks out `$GERRIT_REFSPEC`, falling back to
the branch only when none is given, so a stage can build one reviewed
patchset; it then commits the release version and archives that
**release** commit as a git bundle, both beside the build logs under
`log_dir`. The release job checks out the source commit, fast-forwards
it from the bundle to the release commit, and tags the result
(`release-job.sh`). Tagging the recorded source commit directly would
tag the SNAPSHOT code, not what was staged.

The lane keeps that guarantee through a **stage record**: one durable
object per staged build, written by the stage workflow's `record` job
and read by the release workflow. It holds the project and release
version it staged, the Gerrit refspec or branch it was asked to build
and the exact revision it checked out, the staging repository ID, a
manifest of every staged file with its digest, the release commit as a
bundle, references to the provenance attestations made at stage time,
and, where the project publishes to Central, the Central deployment ID. It
must outlive GitHub artefact retention (see below). Where it lives is
the main question the staging model still has to answer.

### Stage workflow

global-jjb's `gerrit-maven-stage` runs, in one job:

```text
versions-plugin -> maven-patch-release -> build -> SBOM
  -> lf-sigul-sign-dir ($WORKSPACE/m2repo) -> lf-maven-stage -> lf-maven-central
```

The lane keeps that order and splits it across jobs, so no job holding a
credential runs project code:

```text
build ─┬─ sign ─┬─ stage ────────────┐
       │        └─ central (optional)┤
       ├─ attest ────────────────────┼─ record
       ├─ (release commit bundle) ───┘
       └─ sbom ─ grype
```

- **build:** set the release version with `maven-stage-prep-action`
  in `versions-plugin` mode, commit it, `clean deploy` to the `m2repo`,
  and upload both the tree and the release commit as artefacts. No
  credentials. The action's default `sed` mode, like the Jenkins
  `maven-patch-release.sh` it ports, strips `-SNAPSHOT` from every
  `*.xml` in the repository and commits the lot, so a test fixture or
  resource that mentions the string would change in the release. The
  versions plugin touches the reactor's POMs alone.
- **sign:** download the `m2repo`, sign every file in it, upload the
  signed tree. Holds the signing credential and nothing else. This is
  where Sigul goes; see below.
- **stage:** download the signed `m2repo` and stage it with
  `nexus-staging-action`, holding the Nexus credential alone.
- **central:** for a project that publishes to Maven Central, a
  separate job downloads the same signed tree and publishes it with
  `central-publish-action`, holding the Central token alone. Neither
  publishing job sees the other's credential.
- **record:** runs once `stage`, `attest` and, where the project
  publishes to Central, `central` have succeeded, and writes the stage
  record from their outputs, a digest of every file in the signed tree,
  and the build's commit bundle. A Central
  branch skipped because the project does not publish there records no
  deployment; one that failed fails the record. Only a complete record
  is published, so the release workflow never reads a partial one.
- **attest:** download the built `m2repo` and generate build
  provenance for its artefacts, holding `id-token: write` and
  `attestations: write` and nothing else. `actions/attest` asks for
  `artifact-metadata: write` as well, but uses it only to write a
  storage record for an image pushed to a registry (`push-to-registry`),
  which file subjects never are. It runs here, in the run that
  built them, because provenance describes the run that makes it:
  `actions/attest-build-provenance` builds its predicate from the
  current job's OIDC claims (the commit, ref, workflow and run). Run
  from the later release workflow, it would name the release-file merge
  as the source and the release workflow as the builder. Those claims
  name the commit that triggered the run, though, not the one the build
  checked out: a stage of a Gerrit refspec builds a patchset the
  dispatch never named. The job therefore makes two attestations over
  the same subjects. The standard build provenance binds the artefacts
  to this run and workflow; a second, with a lane-defined predicate type
  made through `actions/attest`, records the refspec or branch asked
  for, the source revision checked out and the release commit built
  from it, taken from the build job's outputs. Both carry this run's
  signing identity. The subjects are the unsigned tree: signing then
  adds `.asc` files beside them without changing them, and the release
  workflow verifies those signatures on their own.

The Jenkins job runs signing in the same job as the build, so the
signing credentials sit beside the project's code (gap analysis G-09).
Splitting the job removes that; it is the main change from Jenkins,
and the reason the stage workflow is not a one-job port.

### Signing: Sigul now, the interface fixed

Both projects sign with Sigul, LF's signing bridge, and the lane is
built for it. `sigul-sign-action` is being reworked separately, so the
lane depends only on what each signing point takes and produces, taken
from the global-jjb scripts it replaces. Jenkins signs in three places, the
last of them outside these Maven workflows:

<!-- markdownlint-disable MD013 -->

| Point             | Signs                           | With   | global-jjb source               |
| ----------------- | ------------------------------- | ------ | ------------------------------- |
| Stage, `sign` job | Every file in the `m2repo`      | Sigul  | `sigul-sign-dir.sh`             |
| Release, tag step | The annotated release tag       | Sigul  | `release-job.sh` `tag-git-repo` |
| Container release | Each container image, by digest | cosign | `release-job.sh`                |

<!-- markdownlint-enable MD013 -->

- **Stage artefacts:** a directory in, the built `m2repo`; a detached,
  ASCII-armoured `<file>.asc` beside every file not already `*.asc`,
  the form Nexus staging and Maven Central expect.
- **Release tag:** an annotated tag, signed through Sigul and verified
  against the project's public GPG key before it is pushed. A
  lightweight tag already present blocks the push, as on Jenkins.
- **Container images:** signed by digest with a cosign key pair, not
  keyless. This belongs to a container release lane, not these Maven
  workflows: `cps` stages images in a separate `gerrit-maven-docker-stage`
  job, with its own release file (`distribution_type: container`) and
  its own `log_dir`, and that file names images by tag, not digest. A
  container lane has to record the digests at stage time before cosign
  can sign them. Jenkins downloads cosign from `releases/latest` with no
  pin or checksum; that lane will pin it like every other tool.

Sigul needs the client configuration, key passphrase, NSS PKI bundle
and the bridge's address. On Jenkins these are three managed files
(`sigul-config`, `sigul-password`, `sigul-pki`); here they load through
`credential-load-action` into the signing job alone, never the build.

Each signing job takes an artefact in and hands one on, so what follows
does not care how the signatures were made. Sigstore keyless signing,
if a consumer ever needs it and can reach it, would replace a job, not
reshape the lane. Some Gerrit-mirrored and air-gapped consumers cannot
reach public Sigstore infrastructure, which is why Sigul stays the
default.

### Release workflow

Publication cannot be undone, so everything that can fail runs first.
Jenkins does the opposite: `release-job.sh` promotes to Nexus
(`nexus_release`) and only then tags (`tag-git-repo`), so a tag it
cannot push, such as a lightweight tag already present, leaves a
published release with no tag.

1. `verify-release-schema-action` validates the release file that
   triggered the run. From v1.0.0 it publishes the file's fields as
   outputs (`version`, `log_dir`, `ref`, `git_tag` and the rest), so
   no step re-parses the YAML. The release file and its `log_dir` stay
   the data bus: `log_dir` is what locates the stage record.
2. Read the stage record, and refuse to continue unless its project
   and version match the release file exactly. A stale or mistyped
   `log_dir` would otherwise promote one version and tag another.
   Jenkins checks this by searching the stage job's console log for the
   version string (`release-job.sh` `verify_version_match_release`),
   which a substring can satisfy; the record makes it an exact
   comparison.
3. Verify the staged bytes: authenticate to the closed staging
   repository and download its files. Check each against the record's
   digest manifest, which lists every signed-tree file, `.asc` files
   included; a listed file missing or changed fails the release, as
   does an unlisted one, unless Nexus generated it on close (which
   files it adds is still to be confirmed against a real staging
   repository). Verify both stage-time attestations for the subjects
   they cover, the unsigned artefacts, and that the second names the
   source revision and release commit the record does. No attestation
   covers the signatures, so verify each `.asc` against its file with
   the project's public GPG key. For a project that publishes to
   Central, check the recorded deployment the same way before
   publishing it: the Portal API's status must read `VALIDATED` and
   list the release's coordinates, and each manifest file, fetched from
   that deployment through the Portal's per-deployment download
   endpoint, must match its digest. A stale deployment ID then fails
   here rather than publishing other bytes. Promotion moves files by
   repository ID without looking at them, so this is what binds the
   attested, signed artefacts to the repository being released.
4. In a job of its own, recreate the release commit from the record's
   source revision and bundle, check for a conflicting tag, create the
   annotated tag, sign it through Sigul and verify the signature. Do
   not push it yet. Jobs share no git database, so the job bundles the
   release commit and the signed tag, uploads the bundle as an
   artefact, and outputs the tag object's ID.
5. Only now publish: promote the staging repository with
   `nexus-staging-action`'s `release` mode, under the Nexus credential,
   and, for a project that publishes to Central, publish the deployment
   the record names. The stage uploads with `central-publish-action` in
   its default `USER_MANAGED` mode, which validates without publishing,
   so publication waits for the release; `AUTOMATIC` would publish at
   stage time and break that.
6. Download the tag bundle and fetch the tag from it, check that the
   tag object ID matches step 4's output and its signature still
   verifies, then push the tag. Look up the GitHub release by tag:
   create it when absent, reuse one whose tag names the same commit,
   and fail on any other.

Steps 5 and 6 are the only ones that change anything outside the run,
and each is idempotent: promoting an already-released repository,
pushing the same tag object again, or finding the matching release,
succeeds without change. A Central deployment that an earlier attempt
published reads `PUBLISHING` or `PUBLISHED`; step 3 accepts either in
place of `VALIDATED`, since that attempt matched its files before
publishing them, and step 5 waits for `PUBLISHED` instead of
publishing again. A run that fails after publishing can therefore
simply be re-run.

SBOM and Grype run on both lanes, for information on merges (D-3).
Provenance is part of the release lane, not the merge lane, and is made
at stage time for the reason given above. The release workflow makes no
attestation of its own: it can verify the stage-time attestations
against the staged files before promoting them, since the promotion
moves files by repository ID without downloading them. The Python
release lane attests inside its build job, which holds `id-token:
write` while the project builds; this lane attests in a job of its own
and does not follow it.

### Release-lane prerequisites

`nexus-staging-action` v0.1.1 cannot yet guarantee a complete, closed
candidate, which the release lane depends on:

- **Partial uploads:** stage mode fails only when every upload fails,
  so a staging repository missing files still closes and succeeds.
  Any upload failure must fail the stage.
- **Close is asynchronous:** stage mode requests the close with one
  call to `/finish` and reports success without waiting. Nexus closes
  in the background and runs its staging rules, which can fail; the
  action must poll for the outcome, as its `release` mode already
  checks for the `CLOSED` state before promoting.

Without both, the lane could report a staged candidate and later promote
an incomplete repository, or one whose close failed.

`central-publish-action` v0.1.1 uploads and validates (`USER_MANAGED`)
and reports the `deployment_id`, but has no mode that publishes an
existing deployment by ID, nor one that verifies a deployment's files
before publishing it. The release workflow needs both, or Central
publishing stays out of the first release lane.

### Open questions

- **Nexus2 staging model:** `maven-stage-prep-action` and
  `nexus-staging-action` (`stage`, `close`, `release`, `drop`) exist,
  but the reusable model still needs designing: the staging profile per
  project (OpenDaylight passes `staging-profile-id`), and where the
  stage record lives for the release file's `log_dir` to find. Jenkins
  keeps the equivalent in its log archive; the GitHub equivalent could
  be a release asset or an object store, but not a workflow artefact,
  which expires. A release file picks a staged build whenever the
  project decides to release: `cps` 3.8.1 and 3.8.2 name stage builds
  975 and 978, three builds apart, yet their release files merged seven
  weeks apart.
- **OpenDaylight autorelease:** OpenDaylight also stages and signs
  through its cross-project autorelease and MRI stage jobs. This lane
  covers a single project's stage and release; whether autorelease moves
  onto it is a later decision.

Neither lane ships as a placeholder: each lands complete and functional,
under the filename-prefix convention above.

## Supporting building-block actions

The lanes compose actions from sibling `lfreleng-actions` repos. The
Java-specific enhancements land as separate PRs in those repos before
this repository wires them together:

<!-- markdownlint-disable MD013 -->

| Action                           | Lane                | Role                                                          |
| -------------------------------- | ------------------- | ------------------------------------------------------------- |
| `build-metadata-action`          | All                 | Java version + release metadata detection                     |
| `maven-build-action`             | All                 | Maven setup + lifecycle build                                 |
| `gradle-build-action`            | Verify              | Gradle setup + build (brought to Maven parity)                |
| `junit-test-report-action`       | Verify              | JUnit XML rendering + check                                   |
| `sbom-action`                    | All                 | CycloneDX SBOM generation (cyclonedx backend, resolved graph) |
| `grype-scan-action`              | All                 | Vulnerability scan over the generated SBOM                    |
| `maven-xml-settings-action`      | Merge, release      | Nexus `settings.xml` synthesis                                |
| `maven-snapshot-metadata-action` | Merge               | Seed and prune SNAPSHOT metadata around the deploy            |
| `nexus-publish-action`           | Merge               | Upload the SNAPSHOT `m2repo` to Nexus                         |
| `credential-load-action`         | Merge, release      | Load a publish or signing credential into one job             |
| `maven-stage-prep-action`        | Release             | Version the reactor for a release build                       |
| `nexus-staging-action`           | Release             | Stage, then promote, in Nexus2                                |
| `sigul-sign-action`              | Release             | Sigul signing of artefacts and the release tag (in rework)    |
| `verify-release-schema-action`   | Release             | Validate the release file and publish its fields              |
| `central-publish-action`         | Release             | Maven Central publishing, where a project uses it             |

<!-- markdownlint-enable MD013 -->

The `java-version` input naming was normalised across every build action
before the workflows depended on it, since renaming a consumed input
after the fact would be a breaking change.

## Action pin policy

zizmor's auditor persona rejects `@main`/branch refs (`unpinned-uses`), so
every `uses:` ref is pinned to a full commit SHA with a `# vX.Y.Z` comment
naming the release it targets, matching the template convention. No
building-block action the verify lane composes is consumed from an
unreleased ref: each one had a published release to pin to before the
workflows depended on it.

The pinned versions themselves are not recorded here. Dependabot
maintains them (`.github/dependabot.yml`, weekly, `github-actions`
ecosystem), so a version list in this document would be stale within
days of writing and would put every bump PR in conflict with the
documentation. The `# vX.Y.Z` comment beside each `uses:` ref is the
authoritative record.

## Self-test approach

`testing.yaml` calls the Maven and Gradle verify workflows by
**self-repository path** (`uses: $/.github/workflows/...`), which
resolves this repository at the commit already running. GitHub added
the form in July 2026 and recommends it for a workflow in the same
repository; it replaced the `./` path this brief first recorded, which
resolves identically. Either way the self-test always validates the
current branch. Both self-test jobs
run on **every pull request**.

There is deliberately no `workflow_dispatch` trigger. A manual run
happens on the default branch, which would hand the job a cache token
with write access to the default-branch scope while it builds
third-party code; that code could then poison caches later runs restore
(CWE-349). Pull request runs write only to their own cache scope. This
matches `python-workflows`.

The Maven lane builds `lfreleng-actions/test-maven-project` and the
Gradle lane `lfreleng-actions/test-gradle-project`, both under `block`
egress. Each fixture depends only on JUnit, Jackson and (Gradle)
Commons Lang from Maven Central, so its footprint is the allow-listed
toolchain set, and each keeps Grype's gate strict: the fixtures are
ours, so an advisory in them is ours to fix. The Gradle fixture is a
multi-project build with a grandchild module and both DSL dialects. An
`sbom-check` matrix job then asserts, for each lane, that the SBOM
holds one dependency whose version comes from an imported BOM and one
that arrives only transitively, both with real versions
(`jackson-databind` and `jackson-core` in both fixtures). A passing
Grype scan proves nothing about completeness: the fixtures have no
advisories to find, and a near-empty SBOM scans clean. Without that
assertion both lanes would stay green whatever their SBOMs contained.
The check runs whatever the lanes' verdicts, so a Grype failure cannot
hide it.

Both lanes also set `checkout_submodules`, and the Maven lane sets
`mvn_opts` and `env_vars`, to non-default values that leave the
fixture's graph and egress alone. A `pass-through-check` job then
proves each reached both Maven runs. `mvn_opts` sets a marker
property that surefire records in the uploaded JUnit reports, and
`-DincludeBomSerialNumber=false`, which drops the SBOM's serial
number. `env_vars` sets `MAVEN_OPTS` to
`-Dsurefire.reportNameSuffix=env-vars -DprojectType=application`,
which renames the reports and retypes the SBOM's root component.
Remove any wiring and its mark disappears.

`mvn_pom_file` gets a second Maven call, `maven-pom-test`, since the
first call's `./pom.xml` names the same POM as the fallback. It builds
the fixture's `core/pom.xml` with `-DskipTests` and uploads the
packaged output, and a `pom-check` job asserts that output holds the
`test-maven-core` jar and no `test-maven-app` jar, which a root build
would add. The call disables the SBOM, which rejects that POM, and
leaves tests, JaCoCo and the CBOM off, so it uploads none of the
artefact names the first call uploads for the checks to read. The
first call's `./pom.xml` still runs the SBOM guard's accept path live.
The rejection itself runs in `wiring-check`: a job that calls a
reusable workflow cannot set `continue-on-error`, so a live rejection
would fail the run.

Each fixture carries a git submodule pinning `test-maven-project`'s
first commit, which holds a two-line README and no build. Its
`SubmoduleTest` reads that README: it passes when the checkout fetched
the submodule, fails on the wrong content, and skips when the
directory is empty, so a consumer that checks out without submodules
still builds. A `submodule-check` matrix job reads each lane's uploaded
JUnit reports with `.github/scripts/submodule-check.py` and fails
unless the test passed. A skip fails it too, so removing the wiring or
setting `checkout_submodules: false` turns the run red. The Gradle
fixture declares the submodule directory as an input of its `test`
task, so Gradle cannot reuse a result recorded under another checkout.

The Gerrit path needs more than the fixtures show. A `wiring-check`
job, the structural guard beside that behavioural one, runs
`.github/scripts/wiring-check.sh` over this
branch's workflows. It extracts the POM, environment and
metadata-location guards and runs their accept and reject paths,
including a line break that must not start a workflow command and
names `toUpperCase()` maps onto reserved ones. It requires
`checkout_submodules` on every checkout in both lanes, and the
initialisation step after every Gerrit checkout. It also rebuilds, in
local repositories, the Gerrit path's sequence: the base checkout
`actions/checkout` performs, then a switch to a change that adds a
submodule. It asserts that the plain update leaves the submodule empty,
then that the initialisation step fills it. The self-test cannot run
that path live, since it needs a Gerrit change.

Every building-block action is pinned to a published release, and the
toolchain egress (Maven Central, Gradle distribution, Temurin, and the
syft and grype tool downloads) is in the central harden-runner
allow-list as of `.github` v0.7.0.

The planned merge and release lanes are out of scope for the self-test
until they are added: they need a merged-commit or signed semver tag-push
context that is neither available nor safe on a pull request.

## Conventions inherited from the template

- Workflow `name:` prefixed `[R]`.
- All `workflow_call` inputs `required: false`, lowercase snake_case
  (UPPERCASE `GERRIT_*` names reserved for dispatch inputs on callers).
- Top-level `permissions: {}`; minimal per-job grants with explanatory
  comments; `timeout-minutes` on every job. The build and Grype jobs
  take their timeout from an input (`build_timeout_minutes` 45,
  `grype_timeout_minutes` 30), as do the test summary, SBOM and CBOM
  steps inside the build job (`tests_timeout_minutes` 30,
  `sbom_timeout_minutes` 30, `cbom_timeout_minutes` 30), because their
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
  for the build job only, which includes the SBOM and CBOM steps — for
  dependency fetches from CDNs impractical to enumerate in the
  allow-list — while every other job stays governed by
  `harden_runner_egress`. This is a first, build-scoped hook; per-job
  egress control can be generalised later if further lanes need it.
- Never interpolate `${{ }}` into `run:` blocks; env-mediate dynamic
  values (zizmor template-injection). `with:`-block interpolation is
  safe.
- Dual checkout switch on `gerrit_refspec`
  (`checkout-gerrit-change-action` when set, `actions/checkout`
  otherwise). `checkout_submodules` (boolean, default `false`) drives
  both paths' `submodules` input in every job that checks out, in both
  lanes: a submodule can carry modules, so the build, SBOM and CBOM
  must see the same tree. The legacy lane cloned submodules
  unconditionally; here it is opt-in. `checkout-gerrit-change-action`
  v1.1.0 initialised submodules on the base branch, then ran a plain
  `git submodule update` after switching to the change, which left a
  submodule the change adds or moves uninitialised; v1.1.1 fixed this
  and v1.1.2 also removes submodules the change drops. An
  "Initialise Gerrit change submodules" step after every Gerrit
  checkout still runs `git submodule sync` and
  `git submodule update --init`. Both are idempotent, so the step is
  harmless on a fixed pin and guards against a pin regression.

## Follow-ups

1. Design and implement the merge/release lanes (signing, Nexus2 staging,
   Model B data bus).
2. Wire the ONAP `cps` Gerrit verify/merge workflows onto these reusable
   workflows.
3. Drop the workflows' "Initialise Gerrit change submodules" steps
   and their `wiring-check.sh` rule, now that
   `checkout-gerrit-change-action` v1.1.1 initialises the submodules a
   change adds.
