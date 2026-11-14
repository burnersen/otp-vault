#!/usr/bin/env bash
# otp-vault (https://github.com/burnersen/otp-vault)
# Copyright (C) 2026 burnersen
# SPDX-License-Identifier: GPL-3.0-only
#
# Makes sure the next release has its notes before it is started. The
# release workflow stops when .github/release-notes/<version>.md is missing;
# this check finds that on every push instead of on release day.
#
# Rule: when the program changed since the newest tag, there must be a notes
# file for a version above that tag. Changes to docs, tests and workflows
# alone need none. Needs the tags and history (checkout with fetch-depth 0).
#
#   bash .github/check-release-notes.sh
set -euo pipefail

notes_dir=.github/release-notes
last=$(git tag --list 'v[0-9]*' --sort=-v:refname | head -n 1)
if [ -z "$last" ]; then
  echo "No release yet: nothing to check."
  exit 0
fi
last=${last#v}

# Files that change what users get. Everything else (docs, tests, page
# checks, workflows, notes) can change without a new release note.
changed=$(git diff --name-only "v$last" HEAD -- . \
  ':(exclude)*.md' ':(exclude).github/**' ':(exclude)*_test.go' \
  ':(exclude)frontend/*_check.js' ':(exclude)LICENSE' ':(exclude)_notes/**')
if [ -z "$changed" ]; then
  echo "Nothing for users changed since $last."
  exit 0
fi

# The highest version among the notes, compared by version, not by text.
newest=$(ls "$notes_dir" | sed -n 's/\.md$//p' | sort -V | tail -n 1)
above=$(printf '%s\n%s\n' "$last" "$newest" | sort -V | tail -n 1)
if [ -n "$newest" ] && [ "$above" = "$newest" ] && [ "$newest" != "$last" ]; then
  echo "The next release has its notes: $notes_dir/$newest.md (last release $last)."
  exit 0
fi

echo "::error::the program changed since $last, but no release notes for a newer version exist."
echo "Changed since $last:"
printf '  %s\n' $changed
echo "Write $notes_dir/<next version>.md (e.g. a version above $last) and start the release with that version."
echo "Notes there now: $(ls "$notes_dir" | tr '\n' ' ')"
exit 1
