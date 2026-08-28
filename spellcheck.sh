#!/usr/bin/env bash
#
# Spell-check this project with codespell (US English).
#
# The project root is the directory that contains this script, so it can be
# run from anywhere and always checks the project it lives in.
#
# Usage: ./spellcheck.sh
set -euo pipefail

# Project root = directory holding this script (resolved to an absolute path
# so codespell reports absolute file paths).
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# codespell must be available on PATH.
if command -v codespell >/dev/null 2>&1; then
    CODESPELL="codespell"
else
    echo "codespell not found. Install it with: pip install codespell" >&2
    exit 127
fi

# Generated output, dependencies and binary assets have no spelling to check.
SKIP="*.min.js,*.min.css,*.map,*.json,*.lock,*.svg,*.png,*.jpg,*.jpeg,*.gif"
SKIP="$SKIP,*.ico,*.woff,*.woff2,*.ttf,*.eot,.git,node_modules,build,dist"
SKIP="$SKIP,.next,out,coverage,*.snap,*.egg-info,external,__pycache__,.venv"

exec "$CODESPELL" --skip="$SKIP" "$PROJECT_DIR"
