// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation

// Fixture for the Grype gate's resolved paths in .github/workflows/
// testing.yaml. The Gradle verify lane builds this project from this
// repository at the commit under test, with gradle_version pinned
// since the fixture carries no wrapper, so dependency-change-action
// can resolve the change and write its sidecar; the external fixture,
// checked out at a pinned commit, can only ever report unresolved. A
// single project with no dependencies keeps the build, the SBOM and
// the scan short. gate-verdict-cases builds its changed case from an
// edit to this file, a dependency change by the detector's rules, and
// its unchanged case from an edit to the Java source.
plugins {
    java
}

group = "org.lfreleng.fixture"
version = "0.1.0-SNAPSHOT"

repositories {
    mavenCentral()
}
