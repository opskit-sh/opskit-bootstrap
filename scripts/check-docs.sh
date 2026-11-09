#!/usr/bin/env bash
# Verifies that markdown links across documentation files resolve to existing files.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ERRORS=0

echo "Checking documentation links in ${REPO_ROOT}..."

while IFS= read -r -d '' doc_file; do
    dir="$(dirname "${doc_file}")"
    # Extract markdown links of the form [text](link) where link is a relative file path (not starting with http://, https://, or #)
    while IFS= read -r link; do
        [[ -z "${link}" ]] && continue
        # Strip anchor if present
        target_path="${link%%#*}"
        [[ -z "${target_path}" ]] && continue
        
        # Check if target exists relative to doc directory or repo root
        if [[ ! -e "${dir}/${target_path}" ]] && [[ ! -e "${REPO_ROOT}/${target_path}" ]]; then
            echo "Broken link in ${doc_file}: ${link} -> ${target_path} not found"
            ERRORS=$((ERRORS + 1))
        fi
    done < <(grep -oP '\[.*?\]\(\K[^)]+' "${doc_file}" | grep -vE '^(https?://|mailto:|#)' || true)
done < <(find "${REPO_ROOT}" -name "*.md" -not -path "*/.git/*" -print0)

if [[ ${ERRORS} -gt 0 ]]; then
    echo "FAILED: ${ERRORS} broken link(s) found."
    exit 1
fi

echo "PASS: internal links resolve."
