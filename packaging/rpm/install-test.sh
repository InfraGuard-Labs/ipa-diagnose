#!/usr/bin/env bash
# End-to-end RPM lifecycle verification, run inside a clean Fedora container
# that never had ipa-diagnose baked in. Expects:
#   /rpms/v1/*.rpm   - the "current" build (installed first)
#   /rpms/v2/*.rpm   - a bumped build (used for the upgrade test)
#   /fixtures        - tests/fixtures, mounted read-only, for a real demo run
# Exits non-zero on the first failed check; prints a PASS/FAIL summary line
# per step so failures are easy to spot in captured output/screenshots.
set -uo pipefail

PASS=0
FAIL=0

step() { echo; echo "=== $* ==="; }
check() {
    local desc="$1"; shift
    if "$@"; then
        echo "PASS: ${desc}"
        PASS=$((PASS + 1))
    else
        echo "FAIL: ${desc}"
        FAIL=$((FAIL + 1))
    fi
}

step "1. Fresh install from local RPM file (dnf install ./ipa-diagnose-*.rpm)"
dnf install -y /rpms/v1/*.noarch.rpm
check "package is registered with rpm" rpm -q ipa-diagnose
check "ipa-diagnose is on PATH" bash -c "command -v ipa-diagnose"
INSTALLED_VERSION=$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' ipa-diagnose)
echo "Installed as: ${INSTALLED_VERSION}"

step "2. Runtime dependency check (should have pulled in python3-rich automatically)"
rpm -qR ipa-diagnose
check "python3(rich) dependency resolved" bash -c "rpm -qR ipa-diagnose | grep -q 'python3.*rich'"
check "rich is actually importable in this environment" python3 -c "import rich"

step "3. CLI sanity"
ipa-diagnose --version
ipa-diagnose --help >/dev/null
check "--version reports a version string" bash -c "ipa-diagnose --version | grep -q ipa-diagnose"

step "4. First real run on a non-FreeIPA host (must degrade gracefully, not crash)"
ipa-diagnose diagnose || true
check "runs without crashing when ipa-healthcheck is absent" bash -c "ipa-diagnose diagnose >/dev/null 2>&1; test \$? -le 3"

if [ -d /fixtures/replication/healthy ]; then
    step "5. Demo run against a bundled fixture (--replay)"
    ipa-diagnose --replay /fixtures/replication/healthy diagnose
    check "fixture replay run succeeds" ipa-diagnose --replay /fixtures/replication/healthy diagnose --json
fi

if compgen -G "/rpms/v2/*.noarch.rpm" > /dev/null; then
    step "6. Upgrade to a newer build"
    dnf install -y /rpms/v2/*.noarch.rpm
    NEW_VERSION=$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' ipa-diagnose)
    echo "Now installed as: ${NEW_VERSION}"
    check "version actually changed after upgrade" bash -c "[ '${NEW_VERSION}' != '${INSTALLED_VERSION}' ]"
    check "ipa-diagnose still works after upgrade" ipa-diagnose --version
else
    echo "(skipping upgrade test: no /rpms/v2 provided)"
fi

step "7. Uninstall"
dnf remove -y ipa-diagnose
check "rpm no longer reports the package installed" bash -c "! rpm -q ipa-diagnose >/dev/null 2>&1"
check "ipa-diagnose command is gone" bash -c "! command -v ipa-diagnose >/dev/null 2>&1"

echo
echo "===================================="
echo "RPM lifecycle verification: ${PASS} passed, ${FAIL} failed"
echo "===================================="
[ "${FAIL}" -eq 0 ]
