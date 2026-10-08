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
This repository provides the verify lane (build, test, SBOM and Grype
scan) and the Maven merge lane (SNAPSHOT publish);
[`docs/BRIEF.md`](docs/BRIEF.md) tracks the release lane that follows
later. The workflows keep the harden-runner
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
| `.github/workflows/maven-merge.yaml`               | Maven     | Publish SNAPSHOTs to Nexus             | Merge                |

<!-- markdownlint-enable MD013 -->

These are `workflow_call` reusable workflows; they carry no trigger of
their own. "Caller trigger" is the event on which the shipped
`examples/` callers invoke them: a pull request for the verify lane, and
a merged change or a daily schedule for the merge lane.

## Verify lane

The `maven-build-test.yaml` and `gradle-build-test.yaml` workflows are
complete. A `repository-metadata` job runs in parallel as an
informational step that does not gate the build. Everything that needs
the built tree runs inside `build`. The Grype audit, which needs
nothing but the SBOM document, runs after it (`->` denotes sequence):

```text
build -> grype
```

The `build` job builds the project once and does everything that
depends on the result in the same job, so no job checks out, resolves
or builds it a second time. It detects the project's Java version
through `build-metadata-action`, runs the build with
`maven-build-action` or `gradle-build-action`, then:

1. gathers the JUnit XML, uploads it, and renders it through
   `junit-test-report-action` into the job summary (it does not create a
   check-run);
2. generates a CycloneDX SBOM with `sbom-action` and uploads it;
3. generates a CBOM with `cbom-action` and uploads it.

Each of these runs whatever the build's outcome, so a test failure still
surfaces its report, SBOM and CBOM. The `grype` job then audits the SBOM
under the `grype_fail_on` gate. It stays a separate job because it
judges rather than describes: it reads nothing but the document,
fetches its own vulnerability database, and reports its verdict as a
status of its own.

Both lanes use `sbom-action`'s `cyclonedx` backend, which runs the
CycloneDX Maven or Gradle plugin over the dependency graph the build
resolved, from the local repository or Gradle user home the build
populated. A static scan misses transitive dependencies and BOM-managed
versions in a `pom.xml`, and finds nothing in a Gradle project without a
`gradle.lockfile` (issues #47 and #48). A Gradle wrapper older than the
plugin supports (8.4, or 8.5 on Java 21) skips the SBOM and Grype with a
warning rather than failing the run.

The per-step timeout inputs (`tests_timeout_minutes`,
`sbom_timeout_minutes`, `cbom_timeout_minutes`) each bound their own
step, and each falls within `build_timeout_minutes`, which bounds the
whole job.

The Maven `build` job passes `mvn_opts`, `mvn_pom_file` and `env_vars`
through to `maven-build-action`; each empty value keeps the action's
default. The action deploys into the workspace `m2repo`. From v0.5.1 it
refuses `altDeploymentRepository`, `altReleaseDeploymentRepository` and
`altSnapshotDeploymentRepository` naming anywhere else in `mvn_opts`,
`mvn_params`, `mvn_profiles` or a `MAVEN_ARGS` exported through
`env_vars`, and from v0.5.3 it warns on one naming that `m2repo`, which
has no effect. Remove them from shared build arguments.
Java detection reads the selected POM's directory, and a POM
not named `pom.xml` requires `java_version`. The SBOM step resolves the
graph the build resolves, so it receives `mvn_opts` alongside
`mvn_profiles` and `mvn_params`, and inherits the build's `env_vars`
export. It resolves `path_prefix/pom.xml`, so with `sbom_enabled` set
the build job fails when `mvn_pom_file` names another POM rather than
describe a different project; set `path_prefix` to that POM's directory
instead. `env_vars` takes a JSON object of named
variables in place of `toJSON(vars)`. The export upper-cases each name
and skips one whose variable already holds a non-empty value; it
overwrites a variable that is present but empty. With `sbom_enabled`
set, the build job fails on a name that is not an ASCII identifier, and
on one that either Maven step sets itself, such as `MAVEN_ARGS`. Both
lanes take
`checkout_submodules` (default `false`), which checks out submodules in
every job that checks out the repository, including those a Gerrit
change adds.

The generic template's standalone `audit` job does not appear here: on
the JVM, dependency-risk auditing is the SBOM/Grype chain plus the
separate Sonatype CLM lane, and the build tool (`surefire`/`failsafe` or
the Gradle `test` task) runs the tests as part of its own lifecycle.

### CBOM (informational)

The CBOM steps run `cbom-action` to produce a CycloneDX Cryptography
Bill of Materials: the algorithms, key sizes, modes, protocols and
certificates the code actually calls. An SBOM cannot express that, and
a CBOM is what post-quantum readiness assessments read.

**It never fails the workflow run.** Both steps set `continue-on-error`
and the lane pins the action's `fail_on_error` to `false`, so a scanner
error, a rejected input, or the step timeout all leave the run green.
The scan's timeout is also clamped to what remains of
`build_timeout_minutes`, less a five-minute margin, so the job timeout
cannot land on it; with no time left, the scan skips with a warning.
That covers the whole leg on purpose — there is no `cbom_permit_fail`
input, because the report is advisory by contract rather than by
configuration. Set `cbom_enabled: false` to drop it.

It scans the tree the build job has built, so the scanner resolves
Java symbols against compiled classes rather than bare source, which
`cbom-action` documents as resolving fewer. Dependency jars sit in the
local repository or Gradle user home, outside the directory the action
scans, so they stay out of its reach. Detection also covers specific
cryptographic libraries rather than the whole language; see the
[CBOMkit documentation](https://github.com/PQCA/cbomkit) for which. An
empty CBOM means the scanner found none of those libraries, not that
the code uses no cryptography.

CBOM files upload as `cbom-files-maven` / `cbom-files-gradle` with 45-day
retention, matching the SBOM artefacts. The steps write reports under
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
| `cbom_timeout_minutes` | number  | `30`    | Timeout for the CBOM step, covering the container image pull as well as the scan         |

<!-- markdownlint-enable MD013 -->

## Maven merge lane

`maven-merge.yaml` publishes Maven SNAPSHOTs to a Nexus 2 snapshot
repository when a change merges. The job that runs the project's code
never holds the write credential, and the job holding it never runs
that code. A first job checks the Nexus inputs before anything builds
(`->` denotes sequence, `{ }` parallel jobs):

```text
input check -> { repository-metadata | build -> { publish | grype } }
```

The `build` job checks out the branch head as it stands when the run
starts, sets up the JDK and Maven the deploy uses, then:

1. seeds the published `maven-metadata.xml` of every reactor module
   into the `m2repo` with `maven-snapshot-metadata-action` (`fetch`),
   for the deploy to carry on from the published `buildNumber`, and
   records which modules it read;
2. runs the `deploy` phase with `maven-build-action`, which deploys into
   its fixed `m2repo` and refuses any argument that would redirect the
   deploy. It skips `clean`: the checkout starts fresh and the job
   refuses an existing `m2repo`, so `clean` has nothing to remove, and
   a `maven-clean-plugin` fileset could delete the seeded metadata;
3. refuses any SNAPSHOT coordinate, or metadata, that no module
   `fetch` read owns, such as a coordinate a POM-bound `deploy-file`
   writes inside the reactor's own group, whose `buildNumber` would
   restart at 1; then removes the metadata the deploy left unchanged
   (`prune`), which would otherwise overwrite a sibling build's newer
   copy. Release versions are the next check's to refuse;
4. fails when the `m2repo` holds no deployed artefact, the trace of a
   POM that redirects the deploy itself, holds a file outside the
   reactor's group paths, holds a release version, or holds a symbolic
   link, which the upload would follow past these checks;
5. uploads the `m2repo` as the `maven-merge-m2repo` artefact, kept
   three days, for this attempt's publish job alone;
6. generates the SBOM, whose failure never stops the publish.

The `publish` job downloads the artefact, loads the Nexus password with
`credential-load-action`, and uploads the whole `m2repo` in one
`nexus-publish-action` run, covering every `groupId` the reactor
deploys. That run sends each `maven-metadata.xml` after the files it
describes, and holds them back when any of those uploads fails, so an
artefact missing from one group leaves no group's metadata advertising
it. A failure among the metadata uploads holds back the rest, but
cannot recall metadata already sent.

Retry a failed publish with **Re-run all jobs**. The publish job fails
when "Re-run failed jobs" hands it an `m2repo` from an earlier
attempt: if another run had published since, that older tree would
move the SNAPSHOT back to an older `buildNumber`.
A live run fails when `OP_SERVICE_ACCOUNT_TOKEN` or `VAULT_MAPPING_JSON`
is missing, where the node lane warns and skips: a merge lane that
skipped its publish would leave the SNAPSHOT behind the branch with
every check green. The step summary records the commit built, the group
paths, the metadata seeded and pruned, and the files published and
failed. The `grype` job audits the SBOM for information and never fails
the run. The build and publish jobs add the `nexus_server` host to their
egress allow-lists.

The caller owns the triggers, the Gerrit comments, the wait for
replication, and a concurrency group keyed on the repository; the
[`examples/maven/merge/`](examples/maven/merge/) callers show each, and
[`docs/BRIEF.md`](docs/BRIEF.md) explains why. GitHub does not promise
the order in which queued runs start, so the lane never builds the
triggering commit: each run checks out the branch head when it starts,
and whichever run starts last publishes the newest head **of that
branch**.

That ordering holds within each branch, not across them. Every branch
that publishes must carry its **own SNAPSHOT version**: if `main` and a `stable/*`
branch both build `1.2.0-SNAPSHOT`, whichever run starts last becomes
the newest build Nexus serves, even when its code is older. Bump the
default branch's version when cutting a stable branch, as Jenkins
projects already must; or publish from one branch alone.

Inputs of the merge lane's own:

<!-- markdownlint-disable MD013 -->

| Name                      | Type    | Default     | Description                                                                |
| ------------------------- | ------- | ----------- | -------------------------------------------------------------------------- |
| `nexus_server`            | string  | `''`        | Nexus 2 server URL (`https://`); the lane fails without it                 |
| `repository_name`         | string  | `snapshots` | Snapshot repository to publish to                                          |
| `nexus_username`          | string  | `''`        | Nexus username and 1Password item; empty takes the built repository's name |
| `publish_environment`     | string  | `''`        | GitHub environment for the publish job alone; empty means none             |
| `dry_run`                 | boolean | `false`     | Publish nothing and log each upload URL, with no credential (self-tests)   |
| `gerrit_branch`           | string  | `''`        | Branch a Gerrit change merged into; the lane builds its head               |
| `publish_timeout_minutes` | number  | `30`        | Timeout for the publish job                                                |

<!-- markdownlint-enable MD013 -->

The lane shares `repository`, `ref`, `checkout_submodules`,
`path_prefix`, `java_version`, `mvn_version`, `mvn_profiles`,
`mvn_params`, `mvn_opts`, `mvn_pom_file`, `env_vars`, `sbom_enabled`,
`grype_enabled`, the harden-runner inputs and the build, SBOM and Grype
timeouts with the verify lane, where the `Verify lane` section
describes them. Here `ref` names a branch, as a name or a `refs/heads/`
ref; left empty, the lane builds the triggering branch, and fails when
the trigger is a tag or a pull request rather than a branch. The
metadata fetch reads the reactor with the deploy's profiles, options,
parameters and global settings, and expands the workspace placeholders
in the options and parameters (`${GITHUB_WORKSPACE}` and others) as
`maven-build-action` does, so `mvn_params` must stay within the
reactor-shaping options `maven-snapshot-metadata-action` accepts, and
`env_vars` takes effect before the fetch.

<!-- markdownlint-disable MD013 -->

| Secret                     | Description                                                             |
| -------------------------- | ----------------------------------------------------------------------- |
| `OP_SERVICE_ACCOUNT_TOKEN` | 1Password service-account token for the Nexus password; unless dry run  |
| `VAULT_MAPPING_JSON`       | Base64 JSON mapping organisation to 1Password vault; unless dry run     |
| `maven_global_settings`    | Maven global `settings.xml` for the build job; not the publish password |

<!-- markdownlint-enable MD013 -->

| Output              | Description                                     |
| ------------------- | ----------------------------------------------- |
| `publication_count` | Files the publish job uploaded                  |
| `failed_count`      | Files that failed to upload                     |
| `dry_run_count`     | Files a dry run would upload (`0` otherwise)    |

<!-- markdownlint-enable MD013 -->

The `testing.yaml` self-test runs the lane over `test-maven-project`
with `dry_run`, reading metadata from ONAP's Nexus, where the fixture's
group has never published. A `merge-check` job then asserts each
module's timestamped SNAPSHOT at `buildNumber` 1 with its metadata, and
a dry run covering every file in the `m2repo`. A `merge-prune-check`
job runs the lane's `prune`, at the lane's pin, over the fixture's
reactor plus an extra coordinate inside its group, and asserts that
`prune` refuses it.

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
    merge/               { github.yaml, gerrit.yaml }
  gradle/
    build-test/          { github.yaml, gerrit.yaml }
```

Inputs are optional and default to the canonical behaviour; read the
`inputs:` block at the top of each workflow file for the documented list.

To call a Maven lane more than once in one run, as a matrix of Java or
Maven versions does, give each call its own `artifact_suffix`, for
example `-java-${{ matrix.java }}`. Every artefact name the lane
chooses, for what it uploads or reads back, ends with it, so the calls
cannot read each other's reports, SBOM or `m2repo`. Matrix calls run
as separate jobs, and while `upload-artifact` refuses a name already
used within one job, uploads from separate jobs coexist under one
name, and `download-artifact` takes the newest without an error.
`repository-metadata-action` gives its own upload a unique name
already. A single call leaves the suffix empty and keeps the names
given in this document.

## Gerrit support

The reusable workflows are Gerrit-aware. A verify caller that sets the
`gerrit_refspec` input checks out the change with
`checkout-gerrit-change-action` in place of `actions/checkout`. The
merge workflow has no `gerrit_refspec`: a merged change lives on its
branch, so the merge caller asks Gerrit for the merged commit, waits
for it to reach the GitHub mirror, then passes `gerrit_branch`, and the
lane builds the head of that mirrored branch. Vote and comment casting
live in the `gerrit.yaml` caller examples, never inside the reusable
workflows: the verify callers clear the vote, run and report a vote;
the merge caller reports with comments alone, since Gerrit refuses to
lower a vote on a merged change.

## Testing

[`.github/workflows/testing.yaml`](.github/workflows/testing.yaml)
exercises the Maven and Gradle verify workflows by self-repository path
(`uses: $/.github/workflows/maven-build-test.yaml` and its Gradle
counterpart), which resolves this repository at the commit already
running, so it validates the current branch. Both self-test jobs run on
every pull request. The Maven lane builds the dedicated
`test-maven-project` fixture and the Gradle lane the dedicated
`test-gradle-project` fixture, both under `block` egress. A
`pass-through-check` job proves the Maven lane's `mvn_opts` and
`env_vars` reach both the build and the SBOM, and a `pom-check` job
proves a second Maven call builds the `mvn_pom_file` it names. Each
fixture carries a git submodule and a test that reads it, and a
`submodule-check` job fails unless that test passed in each lane, so
`checkout_submodules` must actually fetch it. A
`wiring-check` job runs `.github/scripts/wiring-check.sh` to test the
guard steps, the merge lane's input checks, its coordinate check and
its copy of `maven-build-action`'s placeholder expansion, and the
submodule wiring the fixtures cannot exercise. See
[`docs/BRIEF.md`](docs/BRIEF.md) for detail.

## Design

Read [`docs/BRIEF.md`](docs/BRIEF.md) for the design decisions: the
Maven/Gradle split, the verify-lane wiring, the removed audit job, the
Maven merge lane, the planned release lane, and the action-pinning
policy.

[pre-commit.ci results page]: https://results.pre-commit.ci/latest/github/lfreleng-actions/java-workflows/main
[pre-commit.ci status badge]: https://results.pre-commit.ci/badge/github/lfreleng-actions/java-workflows/main.svg
