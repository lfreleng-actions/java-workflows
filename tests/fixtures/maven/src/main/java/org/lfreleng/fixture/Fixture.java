/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Linux Foundation
 */
package org.lfreleng.fixture;

/** One class, so the jar the lane packages is not empty. */
public final class Fixture {
  private Fixture() {}

  /** Returns the lane this fixture exists for. */
  public static String lane() {
    return "grype-gate";
  }
}
