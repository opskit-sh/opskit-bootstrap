#!/usr/bin/env bash
# Assemble a production release bundle with test hooks stripped.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <output_directory>" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="$1"

mkdir -p "${OUT_DIR}"
rm -rf "${OUT_DIR}/bin" "${OUT_DIR}/lib" "${OUT_DIR}/keys"
cp -r "${REPO_ROOT}/bin" "${OUT_DIR}/bin"
cp -r "${REPO_ROOT}/lib" "${OUT_DIR}/lib"
cp -r "${REPO_ROOT}/keys" "${OUT_DIR}/keys"
find "${OUT_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${OUT_DIR}" -type f -name "*.py[cod]" -delete 2>/dev/null || true

# Strip compiled test hooks in production bundle
python3 -B -c '
import sys
p = sys.argv[1]
with open(p, "r", encoding="utf-8") as f:
    src = f.read()
target = "readonly OPSKIT_TEST_HOOKS_COMPILED=1"
repl = "readonly OPSKIT_TEST_HOOKS_COMPILED=0"
if target not in src:
    raise SystemExit("Expected OPSKIT_TEST_HOOKS_COMPILED=1 marker in common.sh")
src = src.replace(target, repl, 1)
with open(p, "w", encoding="utf-8") as f:
    f.write(src)
' "${OUT_DIR}/lib/common.sh"

chmod 0755 "${OUT_DIR}/bin/opskit-bootstrap"

# Self-verify production lockdown
for check_env in \
    "OPSKIT_TEST_MODE=1" \
    "OPSKIT_RELEASE_PUBKEY=${OUT_DIR}/keys/release.pub" \
    "OPSKIT_EXPECTED_KEY_ID=opskit-release-2026"
do
    set +e
    out="$(env ${check_env} "${OUT_DIR}/bin/opskit-bootstrap" --dry-run 2>&1)"
    rc=$?
    set -e
    if [[ "${rc}" -ne 8 ]]; then
        echo "FAIL: production bundle did not reject ${check_env} with exit 8 (got ${rc}): ${out}" >&2
        exit 1
    fi
done

echo "Production release bundle created and verified at '${OUT_DIR}'."
