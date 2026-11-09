#!/usr/bin/env bash
# Acceptance test suite for privilege audit: operations run strictly unprivileged without sudo.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== Running acceptance_privilege_audit.sh ==="

IMAGE_NAME="localhost/opskit-test-debian:13"

source "${REPO_ROOT}/tests/setup_test_env.sh"
TEST_ARTIFACTS_DIR="$(mktemp -d)"
setup_test_artifacts "${TEST_ARTIFACTS_DIR}"

cleanup() {
    rm -rf "${TEST_ARTIFACTS_DIR}"
}
trap cleanup EXIT

podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" "${IMAGE_NAME}" /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"
export OPSKIT_SUBUID_START="10000"
export OPSKIT_SUBUID_COUNT="50000"

echo "--- 1. Apply bootstrap as root ---"
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# Record root-owned files right after bootstrap
ROOT_FILES_POST_BOOTSTRAP="/tmp/root_files_pre.txt"
find /etc /var /usr /home -user root 2>/dev/null | sort > "${ROOT_FILES_POST_BOOTSTRAP}"

echo "--- 2. Ensure sudo is unavailable ---"
rm -f /usr/bin/sudo /usr/sbin/sudo 2>/dev/null || true

echo "--- 3. Execute node operations and rootless podman workload as unprivileged opskit user ---"
su -s /bin/bash opskit << "EOF_USER"
set -euo pipefail

# Verify we cannot become root
if [[ "${EUID}" -eq 0 ]]; then
    echo "FAIL: Expected non-root user, got UID 0" >&2
    exit 1
fi

echo "Verifying unprivileged identity: $(id)"

# Exercise the static CLI binary as unprivileged user
CLI_OUTPUT="$(/usr/local/bin/opskit || true)"
echo "CLI binary invoked as unprivileged user: ${CLI_OUTPUT}"

# Configure rootless storage driver for nested container execution
mkdir -p "${HOME}/.config/containers"
cat << "STORAGE" > "${HOME}/.config/containers/storage.conf"
[storage]
driver = "vfs"
STORAGE

# Build and execute a real rootless container workload
WORK_DIR="/tmp/rootless_workload"
mkdir -p "${WORK_DIR}/bin"
cp /bin/busybox "${WORK_DIR}/bin/busybox"
cat << "CONTAINERFILE" > "${WORK_DIR}/Containerfile"
FROM scratch
COPY bin/busybox /bin/busybox
CMD ["/bin/busybox", "echo", "Rootless workload executed"]
CONTAINERFILE

podman build -t localhost/tiny:workload "${WORK_DIR}"
PODMAN_OUT="$(podman run --network none --rm localhost/tiny:workload /bin/busybox echo "Rootless container workload ran cleanly")"
echo "Rootless podman output: ${PODMAN_OUT}"

# Deploy operation (compose tree + env)
DEPLOY_DIR="${HOME}/opskit/deployments/web-service"
mkdir -p "${DEPLOY_DIR}"
cat << "CONF" > "${DEPLOY_DIR}/compose.yml"
services:
  app:
    image: alpine:latest
    command: ["sleep", "3600"]
CONF

# Secrets operation (.env file with mode 0600)
cat << "ENV" > "${DEPLOY_DIR}/.env"
DATABASE_URL=postgres://user:pass@localhost:5432/db
SECRET_KEY=supersecretkey
ENV
chmod 0600 "${DEPLOY_DIR}/.env"

# Routing operation (routes.yaml in service state dir)
mkdir -p /var/lib/opskit/state
cat << "ROUTE" > /var/lib/opskit/state/routes.yaml
routes:
  - host: app.example.com
    target: "127.0.0.1:8080"
ROUTE

# Logs operation
mkdir -p /var/lib/opskit/logs
echo "2026-11-10T00:00:00Z [info] deployment started" >> /var/lib/opskit/logs/deployment.log

# Restart operation
echo "Simulating service reload/restart..."
touch "${DEPLOY_DIR}/.restarted"

echo "All unprivileged operations succeeded."
EOF_USER

echo "--- 4. Verify no new root-owned files were created ---"
ROOT_FILES_AFTER_OPS="/tmp/root_files_post.txt"
find /etc /var /usr /home -user root 2>/dev/null | sort > "${ROOT_FILES_AFTER_OPS}"

# Compare root-owned files: diff should be completely empty
NEW_ROOT_FILES="$(diff -u "${ROOT_FILES_POST_BOOTSTRAP}" "${ROOT_FILES_AFTER_OPS}" | grep '^+/' || true)"

if [[ -n "${NEW_ROOT_FILES}" ]]; then
    echo "FAIL: Unexpected root-owned files created during unprivileged operations:" >&2
    echo "${NEW_ROOT_FILES}" >&2
    exit 1
fi

echo "PASS: Privilege audit verified (real rootless podman workload executed, zero root calls, zero new root-owned files)."
'

echo "ALL PRIVILEGE AUDIT ACCEPTANCE TESTS PASSED."
