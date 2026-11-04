#!/bin/sh
# Print the body of one version's section of CHANGELOG.md, the text between
# "## [VERSION]" and the next "## [" heading. Fails when the section is
# missing or empty, so a release cannot ship without notes.
#
#   scripts/release-notes.sh 0.1.0
set -eu

version="${1:-}"
changelog="${2:-CHANGELOG.md}"
if [ -z "$version" ]; then
  echo "usage: $0 VERSION [CHANGELOG]" >&2
  exit 2
fi

notes="$(awk -v heading="## [$version]" '
  /^## \[/ {
    if (found) exit
    if (index($0, heading) == 1) { found = 1; next }
  }
  found { print }
' "$changelog")"

if ! printf '%s\n' "$notes" | grep -q '[^[:space:]]'; then
  echo "$changelog has no notes under \"## [$version]\"" >&2
  exit 1
fi
printf '%s\n' "$notes"
