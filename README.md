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

Every job after the input checks runs under harden-runner, in `block`
mode by default; see [Egress allow-list](#egress-allow-list) for the
inputs that extend what it allows.

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

### Grype gate policy

By default the `grype` job gates every scan at `grype_fail_on`, as it
always has. These inputs, the same in both lanes, pass the gate policy
of `grype-scan-action` through:

<!-- markdownlint-disable MD013 -->

| Name                             | Type    | Default    | Description                                                                                         |
| -------------------------------- | ------- | ---------- | --------------------------------------------------------------------------------------------------- |
| `grype_gate_when`                | string  | `always`   | `always`, or `dependencies-changed` to gate a change that touched the dependency files              |
| `grype_dependency_policy`        | string  | `declared` | `all`, or `declared` to gate the packages the project declares; inherited ones are warnings         |
| `grype_transitive_fail_on`       | string  | `critical` | Severity from which an inherited package gates anyway, `none` to `critical`                         |
| `grype_only_fixed`               | boolean | `true`     | Gate on findings with a published fix version; a finding without one is a warning                   |
| `grype_remediation_window_days`  | string  | `''`       | Days a finding stays a warning on an unarmed run after its fix appeared; empty turns the window off |
| `grype_remediation_window_start` | string  | `''`       | `YYYY-MM-DD` floor for the window clock; a fix with no date starts there, else gates at once        |
| `grype_dependency_ecosystems`    | string  | `''`       | Comma-separated detection presets, `node` to `docker`; empty means every preset                     |
| `grype_dependency_patterns`      | string  | `''`       | Extra dependency file patterns, one per line, watched beside the presets and the lane's own         |
| `grype_bypass_repository`        | string  | `''`       | `owner/name` holding the approved `BYPASS:` issues; empty means the calling repository              |
| `grype_timeout_minutes`          | number  | `30`       | Timeout for the `grype` job                                                                         |

<!-- markdownlint-enable MD013 -->

Two of these defaults are a change of behaviour from the gate as it
stood, and from what `grype-scan-action` alone would do; both are the
policy agreed for the families, not an oversight. `grype_only_fixed`
defaults to `true`: a finding with a published fix version blocks the
run, and a finding nobody can act on yet appears as a warning, where
before every finding at or above `grype_fail_on` blocked.
`grype_dependency_policy` defaults to `declared`: a finding in a
package the project never asked for, one it inherits through a
dependency, is a warning unless it reaches `grype_transitive_fail_on`,
which defaults to `critical`, where before it blocked at
`grype_fail_on`. The action reads the SBOM's dependency graph to tell
the two apart, and a package it cannot classify counts as declared
and gates. So a caller who takes the defaults now sees an unfixed
finding, or an inherited high-severity one, reported rather than
blocking; `grype_only_fixed: false` and `grype_dependency_policy: all`
restore the previous strictness. The `grype_gate_when` default,
`always`, keeps today's timing: every scan gates.

With `grype_gate_when: dependencies-changed`, the existing
`repository-metadata` job detects dependency changes with
[`repository-metadata-action`](https://github.com/lfreleng-actions/repository-metadata-action#dependency-change-detection),
which runs `dependency-change-action` after its checkout. The job runs
nothing from the project, where the `build` job runs its plugins and
build scripts, and is not a matrix, so one job output,
`dependencies_changed`, carries the verdict to the `grype` job. Any
other call leaves detection off and the output empty. Detection covers
every preset of `dependency-change-action` unless
`grype_dependency_ecosystems` narrows them: over-matching costs a
strict run, where under-matching would let a finding the change
introduced pass as a warning. Detection is repository-wide
(`dependency_path_prefix: '.'`), not scoped to `path_prefix`: a Maven
parent POM or a Gradle included build sits outside the project
directory as often as in it, and a change there must arm the gate; the
cost is one strict run for a dependency change in an unrelated project
of the same repository. The lanes add patterns to the presets: Maven
watches `.mvn/jvm.config`, since a `-D` property set there can select a
dependency version; Gradle watches every `*.gradle` and `*.gradle.kts`,
which covers a convention script a subproject applies; and
`grype_dependency_patterns` adds the caller's own. The `grype` job
needs `repository-metadata` as well as `build`, still runs when the
metadata job failed or skipped, and ignores the verdict unless that
job succeeded. Detection fails closed: an empty verdict, from a
metadata job that failed or skipped or from a change the action could
not resolve, gates the scan as on `always`. Detection needs
`sbom_enabled` on, since without an SBOM no scan consumes its result.
A change that left the dependency files alone then has its findings
reported as warnings, except a finding whose remediation window
(below) has run out, which gates even then; one that touched them
gates as on `always`.
Detection covers the preset's files and the extras listed above, by
name, and nothing inferred from the build's configuration: the action
detects changes to the files that declare or lock dependencies and
does not parse build logic or follow indirection, so a version
catalogue imported from an arbitrary TOML path, a parent POM with a
non-standard file name, a settings file `.mvn/maven.config` selects, a
convention-plugin build outside `buildSrc/` and `build-logic/`, or a
version property passed through `mvn_params` or `build_arguments` is
not a dependency change by its rules. A repository that declares its
dependencies in such a place keeps `grype_gate_when: always`, the
default. The `dependency-change-action` README holds the file list per
preset, how it picks the base commit per event, the fail-closed
contract and the symbolic-link rule; in short, when it cannot prove
what the change touched, the verdict stays empty and the scan gates as
it does today. The base it compares
against depends on how the lane checked out. On a GitHub call it takes
the base from the event and checks that the checked-out commit is the
run's own, `GITHUB_SHA`; it compares commits, not repository or ref
names. A call whose `repository` or `ref` checks out a different
commit stays unresolved and gates, while one that lands on the same
commit resolves as a plain call would. On a Gerrit call, one with a
`gerrit_refspec`, the checkout is the change itself and `GITHUB_SHA`
names the caller's trigger commit rather than the change, so the
action compares the change against its parent (`HEAD^1`) and does not
check `GITHUB_SHA`:
whatever `checkout-gerrit-change-action` fetched is what it measures,
and a Gerrit call resolves rather than gating by default. A symbolic
link or submodule anywhere in the repository that the change did not
touch counts as unresolved under repository-wide detection, so such a
repository always gates. Both presets include files that change for
reasons other than dependencies (`.mvn/maven.config`,
`gradle.properties`, `buildSrc/`, `build-logic/`), at the cost of a
strict run. The `repository-metadata` job's `actions/checkout` fetches
the whole history, which holds the base the action compares against;
`checkout-gerrit-change-action` fetches depth 2 already.

The remediation window bounds that leniency in time. With
`grype_gate_when: dependencies-changed` and a change that left the
dependency chain alone, a finding stays a warning for
`grype_remediation_window_days` days after its fix became available,
then gates as in an armed run; `grype_remediation_window_start` sets
the day the team adopted the window, so an existing backlog gets the
full window. Each finding's clock starts at the later of its fix date
and the start date. A fixable finding for which Grype reports no fix
date has no clock of its own: with a start date set, that date starts
it; with none, the finding gates at once, since a missing date must not
buy unlimited time. Both inputs default to empty, as in the action, and
do nothing on `always` runs. The lanes check every policy input in
`gerrit-validate` by running `grype-scan-action` in the mode that
checks its inputs and stops, with the same inputs the scan gets and
nothing to scan, so a typo fails in seconds rather than after the
build, by the action's own rules. That the step installs no Grype,
fetches no database and makes no network request is the action's
contract, tested in its own repository, which is why the job runs no
harden-runner. The detection presets get a shell check of their own
there, as an input of `repository-metadata-action`, and a bad
`grype_dependency_patterns` entry fails the `repository-metadata` job
by the detector's own grammar.
`grype_bypass_repository` names the repository whose approved `BYPASS:`
issues `grype-scan-action` honours; set it to share one bypass list
across repositories.

Each lane publishes `grype_gate_active` and `grype_gate_reason` (one
line saying why); both are empty when the scan did not run. It also
publishes `grype_dependencies_changed`, the verdict the `grype` job
received: `true` or `false` when detection resolved, empty otherwise.
`grype_gate_active` is `grype-scan-action`'s own verdict, whether a
finding could block the run before `grype_permit_fail` takes effect,
and not a restatement of the dependency-change signal: the value
reads `false` under `grype_fail_on: none` whatever the dependencies
did, and `true` on an unchanged chain once a finding's remediation
window has run out.

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

### Build artefacts

Set `upload_build_artifacts: true` and either lane uploads its packaged
output, kept for `build_artifact_retention_days` (default 7). Each lane
publishes the artefact as workflow outputs, so a caller's next job, a
container build or a publish, can download it without re-deriving a
name that depends on the run:

| Output                 | Value                                         |
| ---------------------- | --------------------------------------------- |
| `build_artifact_name`  | The artefact's name; empty when none uploaded |
| `build_artifact_shape` | `m2repo`, `reactor` or `none`                 |
| `build_artifact_count` | Jars, wars and ears collected (plus POMs)     |

The shape is the layout contract:

- **`reactor`.** Each packaged file sits at its path below `path_prefix`:
  a Maven module's `target/` files (`app/target/app-1.0.jar`), a Gradle
  project's `build/libs/` files (`app/build/libs/app-1.0.jar`), nested
  projects at their full depth. Download the artefact into the
  directory `path_prefix` names, and each module finds its output where
  its own build left it: a Dockerfile in `app/` can `COPY target/*.jar`
  (Maven) or `COPY build/libs/*.jar` (Gradle). The Maven lane takes this
  shape when no deploy phase ran, as with its default `clean install`,
  and the Gradle lane takes no other.
- **`m2repo`.** A Maven repository tree (`groupId/artifactId/version/`)
  under a top-level `m2repo/` directory, from a deploy phase, as Nexus
  staging and `nexus-publish-action` consume it. The Maven lane alone
  produces it, when `mvn_phases` deploys.
- **`none`.** The lane uploaded nothing: `upload_build_artifacts` was
  off, the build packaged nothing, or the upload failed. The name is
  then empty.

To build a container image from a `reactor` artefact, chain the lane to
the `docker-workflows` `build-test.yaml` workflow through its
`build_artifacts` input. That input downloads each named artefact into
`path_prefix` by default, so the `reactor` layout lands where each
module's Dockerfile expects it. The `docker-workflows` repository holds
the full, runnable caller in
[`examples/build-artifacts/github.yaml`](https://github.com/lfreleng-actions/docker-workflows/blob/main/examples/build-artifacts/github.yaml).

<!-- markdownlint-disable MD013 -->

```yaml
jobs:
  build-test:
    uses: lfreleng-actions/java-workflows/.github/workflows/maven-build-test.yaml@<sha>
    with:
      upload_build_artifacts: true
  image:
    needs: build-test
    if: needs.build-test.outputs.build_artifact_shape == 'reactor'
    uses: lfreleng-actions/docker-workflows/.github/workflows/build-test.yaml@0a748986df8f93fd610655ee4ffe357cf6d06c4a  # v0.11.3
    with:
      build_artifacts: '[{"name": "${{ needs.build-test.outputs.build_artifact_name }}"}]'
```

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

Every job after the input checks runs under harden-runner, in `block`
mode by default; see [Egress allow-list](#egress-allow-list) for the
inputs that extend what it allows.

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
the run: its policy inputs default to `grype-scan-action`'s own values
and shape the report, while the scan keeps `permit-fail` on and the job
continues on error. The lane's input check runs `grype-scan-action`
before the build in the mode that checks its inputs and stops, with
the same inputs the scan gets and nothing to scan, so a bad policy
value fails in seconds by the action's own
rules; as in the verify lanes, that the step makes no network request
is the action's contract, which is why the job runs no harden-runner.
The build and publish jobs add the `nexus_server` host to their
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

| Name                       | Type    | Default     | Description                                                                           |
| -------------------------- | ------- | ----------- | ------------------------------------------------------------------------------------- |
| `nexus_server`             | string  | `''`        | Nexus 2 server URL (`https://`); the lane fails without it                            |
| `repository_name`          | string  | `snapshots` | Snapshot repository to publish to                                                     |
| `nexus_username`           | string  | `''`        | Nexus username and 1Password item; empty takes the built repository's name            |
| `publish_environment`      | string  | `''`        | GitHub environment for the publish job alone; empty means none                        |
| `dry_run`                  | boolean | `false`     | Publish nothing and log each upload URL, with no credential (self-tests)              |
| `gerrit_branch`            | string  | `''`        | Branch a Gerrit change merged into; the lane builds its head                          |
| `publish_timeout_minutes`  | number  | `30`        | Timeout for the publish job                                                           |
| `grype_fail_on`            | string  | `medium`    | Severity from which the scan reports a failure, `negligible` to `critical`, or `none` |
| `grype_only_fixed`         | boolean | `false`     | Count a finding when it has a published fix version                                   |
| `grype_dependency_policy`  | string  | `all`       | `all`, or `declared` to count the packages the project declares                       |
| `grype_transitive_fail_on` | string  | `none`      | Severity from which an inherited package counts anyway under `declared`               |
| `grype_bypass_repository`  | string  | `''`        | `owner/name` holding the approved `BYPASS:` issues; empty means this repository       |
| `grype_timeout_minutes`    | number  | `30`        | Timeout for the `grype` job                                                           |

<!-- markdownlint-enable MD013 -->

The lane shares `repository`, `ref`, `checkout_submodules`,
`path_prefix`, `java_version`, `mvn_version`, `mvn_profiles`,
`mvn_params`, `mvn_opts`, `mvn_pom_file`, `env_vars`, `sbom_enabled`,
`grype_enabled`, the harden-runner inputs and the build and SBOM
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
a dry run covering every file in the `m2repo`. A `merge-env-check` job
asserts that the lane's own `env_vars` export ran and that the value
reached the SBOM. A `merge-prune-check`
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

## Egress allow-list

Every job after the input checks in the three lane workflows loads its
egress allow-list with `harden-runner-block-action`, then runs
harden-runner against it. Five inputs, the same in every lane, control
that list:

<!-- markdownlint-disable MD013 -->

| Input                                  | Type    | Default                       | Effect                                                         |
| -------------------------------------- | ------- | ----------------------------- | -------------------------------------------------------------- |
| `harden_runner_egress`                 | string  | `'block'`                     | `'audit'` permits all egress and logs it; anything else blocks |
| `harden_runner_allowlist`              | string  | organisation list, pinned     | The baseline allow-list                                        |
| `harden_runner_supplemental_allowlist` | string  | `''`                          | A second list merged with the baseline                         |
| `harden_runner_supplemental_unpinned`  | boolean | `false`                       | Lets the supplemental list follow its default branch           |
| `harden_runner_extra_endpoints`        | string  | `''`                          | Inline `host[:port]` endpoints merged into the list            |

<!-- markdownlint-enable MD013 -->

The supplemental list uses the same coordinate grammar as
`harden_runner_allowlist`. A list in the caller's own organisation may
omit `@ref` and follow its default branch, so an ONAP caller can track
its own list as it changes:

```yaml
    with:
      harden_runner_supplemental_allowlist: 'onap//'
      harden_runner_supplemental_unpinned: true
```

A list in any other organisation must carry a pinned `@ref`; the
action refuses an unpinned list from outside the caller's
organisation, whatever `harden_runner_supplemental_unpinned` says.

Naming a supplemental list makes the job depend on it: the workflows
set the action's `supplemental_required` whenever
`harden_runner_supplemental_allowlist` is non-empty, so a list the
action cannot find fails the job at the allow-list step, not at the
first blocked connection.

`harden_runner_extra_endpoints` takes `host[:port]` tokens separated
by spaces or newlines. It suits a short-term fix while a change to the
allow-list lands; the list stays the lasting home for an endpoint, since
it reaches every caller and keeps a reviewed history.

An unpinned list changes under the caller between runs. The action's
`supplemental_source` and `supplemental_sha` outputs record which list
each run loaded and at which commit, so an audit can tell what a given
run allowed.

## Supported Java, Maven and Gradle versions

[`.github/workflows/java-maven-versions.yaml`](.github/workflows/java-maven-versions.yaml)
lists the Maven and Gradle releases and the Java versions the Java
estate tests against, and publishes them as JSON outputs. This
repository's self-test runs its compatibility matrices from it. The
Maven actions and `gradle-build-action` are to run theirs from it too,
each pinning it by commit, so that a change made there reaches every
repository through the Dependabot bump of its pin. The file name
predates Gradle; callers pin it by path, so it stays.

| Axis   | Versions                                                       |
| ------ | -------------------------------------------------------------- |
| Maven  | 3.9 (3.9.16), 3.10 (3.10.0), 4.0 (4.0.0-rc-7)                  |
| Gradle | 8 (8.14.6) on Java 17 to 24, 9 (9.8.1) on Java 17 to 25        |
| Java   | 17, 21, 22, 23, 24, 25 (Temurin)                               |

Maven 3.9 and 3.10 are the two lines the Apache Maven project
maintains; 4.0 is not yet GA, and the estate tests it ahead of that.
Gradle 9 and 8 are the two lines Gradle maintains, 8 for security
fixes. Java starts at 17, the floor Maven 4 and Gradle 9 require, and
runs from 21 through every feature release to 25, the current LTS, so
a JDK change that breaks a build shows up in the release that
introduced it.

Maven runs on every Java version listed, so Maven matrices take the
cross product of the `maven` and `java` outputs. Gradle does not:
each release runs on a bounded range of Java versions, and Gradle 8
stops at Java 24. The `gradle_cells` output lists the combinations
Gradle supports and no others, for use as a matrix `include`.

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
`checkout_submodules` must actually fetch it. Three calls run under
`grype_gate_when: dependencies-changed`. `maven-gate-test` builds the
fixture at a pinned commit, which is not the commit the run is for,
and detection reports unresolved; its `gate-check` job asserts the
lane's `grype_gate_active` is `true` and its
`grype_dependencies_changed` empty. `maven-gate-resolved` and
`gradle-gate-resolved` build the small projects under
`tests/fixtures/maven` and `tests/fixtures/gradle` in this repository,
at the run's own commit, where detection resolves; the
`gate-resolved-check` job requires the lane's
`grype_dependencies_changed` to be `true` or `false`, since on a pull
request of this repository the action resolves by its own rules, and
holds the lane's `grype_gate_active` to it, which the two agree on
under the lane's policy (a blocking `grype_fail_on`, no remediation
window). Which value the pull request earns is the detector's call and
is not re-derived; `gate-verdict-cases` proves each value instead, on
a change built for it: per lane and case it starts a scratch
repository from the fixture, commits one known change (the fixture's
`pom.xml` or `build.gradle.kts`, or a Java source), runs
`repository-metadata-action` with the lane's patterns and an explicit
base, asserts the `dependencies_changed`, `dependency_change_reason`
and `dependency_change_base` outputs it expects, then runs
`grype-scan-action` with the
lane's policy over the resolved lane's SBOM and asserts `gate-active`
is `false` for the unchanged case and `true` for the changed one.
`gate-validate-check` runs the lanes' validation step itself, at the
lanes' pin with the lanes' defaults and a `grype_gate_when` the action
does not know, as the lanes' job runs it, and asserts the step fails:
a typo fails in seconds. It proves nothing about the network, which
is the action's own contract. A
`wiring-check` job runs the `unittest` suite under `tests/` with
`uv run --locked python -B -m unittest discover -s tests -v`.
`tests/test_wiring.py` tests the guard steps, the merge lane's input
checks, its coordinate check and its copy of `maven-build-action`'s
placeholder expansion, the submodule wiring the fixtures cannot
exercise, and that every artefact name the Maven lanes use carries
`artifact_suffix`; `tests/test_grype_gate.py` holds both lanes to the
Grype gate policy's wiring: that each lane's input check,
`gerrit-validate` in the verify lanes and the merge lane's own,
validates through the action at the scan's pin with the scan's
own expressions and fixed values
and fetches nothing else, with the presets' shell check run as
extracted, the detection inputs on the `repository-metadata` step, its pin, job
output, checkout depth and position, the `grype` job's `needs`,
condition and guarded verdict, the download of the SBOM alone by its
upload's ID, the absence of the old detection job and sidecar, each
new input's declaration and pass-through, the verdict outputs, the
self-test calls, that no
symbolic link or submodule sits in this repository's tree, and that
`gate-verdict-cases` runs both actions at the lanes' pins with the
lanes' inputs and the expected verdict fixed per case, and that
`gate-validate-check` passes the lanes' defaults with a `gate-when`
the action rejects, runs that one action, and judges the outcome.
Each structural rule also runs against a copy of the workflow with
that one thing wrong, and must reject it, so a rule that stops
rejecting fails the suite. A lookup by step name or `id` fails when a
job carries two, and a
key written twice fails the parse, a bare `on` and a quoted `"on"`
counting as one key, so a second, drifted copy cannot hide behind a
first that matches. Each workflow is also read with PyYAML's
`BaseLoader`, where every key is the text written, and the keys must
agree with the `SafeLoader` reading at every level, the top-level `on`
aside, so a key PyYAML would retype (`off`, `no`, `null`, a bare
number) fails the suite with its path rather than hide its entry from
a lookup by name; `tests/test_helpers.py` holds each lookup to that.
Run it locally with the same command; `uv` installs the locked
interpreter and PyYAML from `uv.lock`. The structural tests need nothing
more. The tests that run a guard extracted from a workflow need what
`ubuntu-latest` has and stock macOS lacks: bash 4 or later, which the
merge lane's input check lower-cases with, and `jq`, which the
environment guards read their JSON with. `tests/guards.py` lists the
two with the guard each serves. On a host without one of them, stock
macOS or a Linux machine for one, the suite skips those
tests and names the missing tool, and on the `ubuntu-latest` runner,
known by `GITHUB_ACTIONS` and `RUNNER_OS`, it skips nothing. The suite
takes git and bash for granted, as every test in this organisation
does.

The `compatibility-verify` and `compatibility-merge` jobs then run both
Maven lanes once for every Maven release and Java version in
`java-maven-versions.yaml`, 18 calls each, and `compatibility-gradle`
runs the Gradle lane once for each of its 11 `gradle_cells`. A matrix
of reusable workflow calls returns one call's outputs alone, so
`compatibility-check` reads every call's artefacts instead, through
`.github/scripts/compatibility-check.sh` for the Maven lanes and
`.github/scripts/gradle-compatibility-check.sh` for the Gradle lane.
They fail on a missing call, on a call whose recorded `mvn --version`
or `gradle --version` names another release or Java version than the
one asked for, on an SBOM without the fixture's resolved
dependencies, and, for Maven, on Surefire reports from another JDK or
an `m2repo` that fails `.github/scripts/merge-check.sh` or holds jars
another JDK built. The Gradle fixture compiles through a Java 17
toolchain, so for Gradle the launcher JVM in the record is the proof
of the JDK under test. A lane called without an `artifact_suffix`
records no toolchain. A failed cell publishes no toolchain record, and
a re-run replaces a cell's artefacts rather than adding to them. A
cell that fails before uploading leaves an earlier attempt's
artefacts behind, so both checks first read the run's jobs, with
`actions: read` on those two jobs alone, and
`.github/scripts/latest-attempt-check.sh` fails a cell whose build
job did not succeed in its latest attempt before reading its
artefacts. See [`docs/BRIEF.md`](docs/BRIEF.md) for detail.

The Gradle self-test call also sets the three supplemental
[egress allow-list](#egress-allow-list) inputs to values that grant
nothing new, so every pull request runs the pass-through in `block`
mode.

## Design

Read [`docs/BRIEF.md`](docs/BRIEF.md) for the design decisions: the
Maven/Gradle split, the verify-lane wiring, the removed audit job, the
Maven merge lane, the planned release lane, and the action-pinning
policy.

[pre-commit.ci results page]: https://results.pre-commit.ci/latest/github/lfreleng-actions/java-workflows/main
[pre-commit.ci status badge]: https://results.pre-commit.ci/badge/github/lfreleng-actions/java-workflows/main.svg
