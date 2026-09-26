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

`sbom` generates a real CycloneDX document with `sbom-action` and feeds
the JSON output to `grype`, honouring `grype_fail_on`, `grype_permit_fail`
and the `NO_BLOCK_AUDIT_FAIL` repository variable (carried verbatim from
the template). With the action's defaults it writes `sbom-cyclonedx.json`
and `sbom-cyclonedx.xml` at the workspace root — the JSON document is the
Grype job's scan contract — and reports the component count to the job
summary. Because the SBOM job does its own checkout and does not depend on
the build's artefacts, it still produces a dependency-scan signal when the
build fails.

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
Neither compiles, so the job still succeeds when the build fails on a
test, and fails only when resolution fails, where there is no graph to
describe. Test-scoped dependencies (Gradle test configurations) stay
out: the SBOM describes the shipped artefact. Each lane names its build
tool through `dependency_manager` rather than leaving the action to
infer it.

`cyclonedx-gradle-plugin` needs Gradle 8.4 or newer, rising with the
JDK (8.5 on the default Java 21). Below that floor the backend skips
and writes no document. The SBOM job runs the same Gradle the build
does. By default that is the project's wrapper, whose version
`build-metadata-action` reports. When a caller pins `gradle_version`,
the build runs a provisioned Gradle instead, so the SBOM job
provisions the exact version the build resolved and removes `gradlew`
from its own checkout, since `sbom-action` always prefers the wrapper.
Either way the lane passes that version to the floor check, which then
settles before anything downloads. A skip raises a warning and a job
summary line, uploads nothing and skips Grype, rather than failing the
upload on a missing file and misattributing an old Gradle to a broken
SBOM job.

The `cyclonedx` backend runs the build tool over the checkout. Maven
loads project extensions, and evaluating a Gradle build runs its build
scripts, so the checkout is executable input. The action's
`untrusted_checkout: auto` would skip on a fork pull request, losing the
SBOM, and cannot recognise a Gerrit change at all. The workflows set
`untrusted_checkout: 'false'` instead: each build job already runs the
same build over the same checkout with the same read-only token and
settings, so the SBOM job exposes nothing the build job does not.

The SBOM job resolves the graph the build resolves. It uses the same
Java version, and the Maven lane provisions the same `mvn_version`
(`sbom-action` runs whichever `mvn` is on `PATH`) and passes the same
`mvn_profiles`, `mvn_params` and `maven_global_settings`, since each
can add modules, repositories or dependency versions. The Gradle lane
forwards the property options in `build_arguments` (`-P`/`-D` and their
long forms), leaving out tasks and other flags. The settings secret is
written to a private file under `RUNNER_TEMP` only when set, and
removed on `always()`. One difference remains: `maven-build-action`
expands workspace variables such as `${GITHUB_WORKSPACE}` in
`mvn_params`, and the SBOM path passes them to Maven unexpanded.

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
3. `maven-snapshot-metadata-action` in `fetch` mode. It runs
   `help:effective-pom` once over the reactor, then seeds the published
   `maven-metadata.xml` for every module into the `m2repo`, so
   `maven-deploy-plugin` carries on from the published `buildNumber`.
4. `maven-build-action` with `mvn-phases: clean deploy`, deploying to its
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
5. `maven-snapshot-metadata-action` in `prune` mode, removing metadata
   the deploy left unchanged, which would otherwise overwrite newer
   copies a sibling build published meanwhile.
6. Upload the pruned `m2repo` as the hand-off artefact, kept three days:
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
  ```

  This departs from the legacy caller, which keys on the branch. Every
  version of an artifact shares one artifact-level `maven-metadata.xml`,
  so lanes for two branches, at `1.1.0-SNAPSHOT` and `1.0.1-SNAPSHOT`
  say, would each add their version and the later publish would drop
  the other's. A running lane is never cancelled, since one stopped
  between fetch and publish would leave the numbering behind.
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
first records the **source** commit, the branch head it built from, in
`taglist.log`; it then commits the release version and archives that
**release** commit as a git bundle, both beside the build logs under
`log_dir`. The release job checks out the source commit, fast-forwards
it from the bundle to the release commit, and tags the result
(`release-job.sh`). Tagging the recorded source commit directly would
tag the SNAPSHOT code, not what was staged.

The lane keeps that guarantee through a **stage record**: one durable
object per staged build, written by the stage workflow and read by the
release workflow. It holds the project and release version it staged,
the staging repository ID, the source commit, the release commit as a
bundle, the attestation subjects, and, where the project publishes to
Central, the Central deployment ID. It
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
build ─┬─ sign ─┬─ stage
       │        └─ central (where the project publishes there)
       └─ sbom ─ grype
```

- **build:** set the release version with `maven-stage-prep-action`
  (Jenkins uses the versions plugin, or strips `-SNAPSHOT` from every
  POM), commit it, `clean deploy` to the `m2repo`, and upload both the
  tree and the release commit as artefacts. No credentials.
- **sign:** download the `m2repo`, sign every file in it, upload the
  signed tree. Holds the signing credential and nothing else. This is
  where Sigul goes; see below.
- **stage:** download the signed `m2repo` and stage it with
  `nexus-staging-action`, holding the Nexus credential alone.
- **central:** for a project that publishes to Maven Central, a
  separate job downloads the same signed tree and publishes it with
  `central-publish-action`, holding the Central token alone. Neither
  publishing job sees the other's credential.

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
   comparison. Only then promote its staging repository with
   `nexus-staging-action`'s `release` mode, under the Nexus credential.
3. For a project that publishes to Central, publish the deployment the
   stage record names. The stage workflow uploads with
   `central-publish-action` in its default `USER_MANAGED` mode, which
   validates without publishing, so publication waits for the release,
   as the Nexus promotion does. `AUTOMATIC` would publish at stage time
   and break that.
4. Recreate the release commit from the stage record's source commit
   and bundle, tag it with a Sigul-signed annotated tag, and create the
   GitHub release, the signing in a job of its own.

SBOM and Grype run on both lanes, for information on merges (D-3).
Attestation runs on the release path alone and, like signing, in its
own job, as the node lane's `attest` job does. The Nexus promotion
moves files by repository ID without downloading them, so the job
attests the subjects the stage record lists, verified against the
closed staging repository, rather than a build artefact long gone. The
Python release lane attests inside its build job, which holds
`id-token: write` while the project builds; this lane deliberately does
not follow it.

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
existing deployment by ID. The release workflow needs one, or Central
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

The Maven lane builds `lfreleng-actions/test-maven-project` under
`block` egress: the fixture is a three-module reactor depending only on
JUnit and Jackson from Maven Central, so its footprint is the
allow-listed toolchain set. An `sbom-check` matrix job then asserts,
for each lane, that the SBOM holds one dependency whose version comes
from an imported BOM and one that arrives only transitively, both with
real versions (`jackson-databind` and `jackson-core` for Maven; the
webflux starter and `spring-core` for Gradle). A passing Grype scan
proves nothing about completeness: the Maven fixture has no advisories
to find, and a near-empty SBOM scans clean. Without that assertion
both lanes would stay green whatever their SBOMs contained. The check
runs whatever the lanes' verdicts, so a Grype failure cannot hide it.

The Gradle lane sets `grype_permit_fail`: its upstream project's
resolved graph carries published advisories (Netty, Jackson, PostgreSQL
and others, reached through Spring Boot), and a pinned upstream commit
only accumulates more. The job tests the workflow, not that project's
dependency hygiene, so it reports those findings without failing on
them. The Maven fixture is ours, and its gate stays strict.
The Gradle lane still builds a pinned upstream project under `audit`
egress, because no `test-gradle-project` fixture exists yet (issue #50).
A large upstream project reaches endpoints beyond the toolchain set; a
dedicated fixture with a known footprint can switch it to block mode.

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
  for the build and SBOM jobs only — for dependency fetches from CDNs
  impractical to enumerate in the allow-list — while every other job
  stays governed by `harden_runner_egress`. The Maven SBOM job shares
  the switch because it resolves the same dependency graph the build
  does. This is a first, build-scoped hook; per-job egress control can
  be generalised later if further lanes need it.
- Never interpolate `${{ }}` into `run:` blocks; env-mediate dynamic
  values (zizmor template-injection). `with:`-block interpolation is
  safe.
- Dual checkout switch on `gerrit_refspec`
  (`checkout-gerrit-change-action` when set, `actions/checkout`
  otherwise).

## Follow-ups

1. Create a `test-gradle-project` fixture and point `testing.yaml` at it
   (issue #50). The Maven fixture is already in use.
2. Design and implement the merge/release lanes (signing, Nexus2 staging,
   Model B data bus).
3. Wire the ONAP `cps` Gerrit verify/merge workflows onto these reusable
   workflows.
