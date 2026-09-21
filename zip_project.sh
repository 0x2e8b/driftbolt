#!/usr/bin/env bash
set -euo pipefail

# Zips the current git repository, respecting .gitignore.
# Usage: ./zip_project.sh [output.zip]

OUTPUT="${1:-$(date +%Y%m%d)_sycope_recorder.zip}"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Error: must be run inside a git repository" >&2
    exit 1
fi

rm -f "$OUTPUT"

git ls-files -z --cached --others --exclude-standard \
    | xargs -0 zip -q "$OUTPUT"

echo "Created $OUTPUT"
