#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation
#
# Defines expand_workspace_vars, sourced by the action steps that pass
# arguments to Maven. It lives in a file rather than in each step
# because the build, the JaCoCo mode resolver and the aggregate report
# pass all have to read the arguments Maven actually receives; a copy
# per step would let them drift apart and disagree about a path.
# Maven interpolates ${...} only in a value reaching it through POM
# interpolation. A user property a plugin reads directly,
# -Djacoco.dataFile or -Dsonar.* among them, keeps the literal text,
# and the shell does not help either: it word-splits an argument
# string but never re-expands ${...} inside the value. Jenkins
# expanded these before Maven started, so a caller writing an
# absolute workspace path reasonably expects the same.
# Expand a fixed list of workspace variables. Bash string operations
# rather than eval or a subprocess: nothing here executes, so $(...),
# backticks and $((...)) stay inert, and the caller gains no
# dependency beyond the shell it already runs in. The name list is
# explicit because the calling step's environment holds GITHUB_TOKEN
# and whatever env-secrets the caller injected; anything outside the
# list, including Maven's own ${project.*} and ${settings.*}, passes
# through for Maven to resolve.
expand_workspace_vars() {
  local text="$1" out='' head rest raw name value
  local allow=' GITHUB_WORKSPACE GITHUB_REPOSITORY GITHUB_REF_NAME'
  allow="$allow GITHUB_SHA GITHUB_RUN_ID RUNNER_TEMP RUNNER_OS "
  while [ "${text#*'$'}" != "$text" ]; do
    head="${text%%'$'*}"
    rest="${text:${#head}+1}"
    if [[ "$rest" =~ ^\{[A-Za-z_][A-Za-z0-9_]*\} ]]; then
      raw="${BASH_REMATCH[0]}"
      name="${raw:1:${#raw}-2}"
    elif [[ "$rest" =~ ^[A-Za-z_][A-Za-z0-9_]* ]]; then
      raw="${BASH_REMATCH[0]}"
      name="$raw"
    else
      # A '$' introducing anything else -- '(', a backtick, a
      # digit -- keeps its literal text and its meaning here,
      # which is none.
      out="$out$head\$"
      text="$rest"
      continue
    fi
    if [ "${allow#* "$name" }" != "$allow" ]; then
      value="${!name-}"
    else
      value="\$$raw"
    fi
    out="$out$head$value"
    text="${rest:${#raw}}"
  done
  printf '%s' "$out$text"
}
