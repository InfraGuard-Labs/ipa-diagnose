#!/usr/bin/env bash
# End-to-end RPM lifecycle verification for the EL8 (python39) build, run
# inside a clean image that never had python39 or ipa-diagnose baked in -
# only what a normal admin following the README would run themselves.
# Expects:
#   /rpms/v1/*.rpm   - the "current" build (installed first)
#   /rpms/v2/*.rpm   - a bumped build (used for the upgrade test), optional
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

step "0. Baseline: confirm system python3 is untouched BEFORE install"
/usr/bin/python3 --version
check "system python3 is EL8's default 3.6.8 before install" bash -c "/usr/bin/python3 --version 2>&1 | grep -q '3\\.6\\.8'"

step "1. Fresh install from local RPM file (dnf install ./ipa-diagnose-*.rpm)"
dnf install -y /rpms/v1/*.noarch.rpm
check "package is registered with rpm" rpm -q ipa-diagnose
check "ipa-diagnose is on PATH" bash -c "command -v ipa-diagnose"
INSTALLED_VERSION=$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' ipa-diagnose)
echo "Installed as: ${INSTALLED_VERSION}"

step "2. System python3 must remain untouched AFTER install"
/usr/bin/python3 --version
check "system python3 is still EL8's default 3.6.8 after install" bash -c "/usr/bin/python3 --version 2>&1 | grep -q '3\\.6\\.8'"
check "python39 module was pulled in as the runtime dependency" bash -c "rpm -q python39 >/dev/null 2>&1 || command -v /usr/bin/python3.9 >/dev/null 2>&1"

step "3. Runtime dependency check (must NOT require system python3/python3.14, only python39)"
rpm -qR ipa-diagnose
check "does not Require the default python3(abi) 3.6 interpreter" bash -c "! rpm -qR ipa-diagnose | grep -Eq 'python\\(abi\\) = 3\\.6|/usr/bin/python3\\.6|/usr/libexec/platform-python'"
check "does not Require python3.14 or any other unrelated interpreter" bash -c "! rpm -qR ipa-diagnose | grep -q 'python3\\.14'"
check "rich is bundled, not an external Requires (no python*dist(rich))" bash -c "! rpm -qR ipa-diagnose | grep -qi 'dist(rich)'"

step "4. CLI sanity"
ipa-diagnose --version
ipa-diagnose --help >/dev/null
check "--version reports a version string" bash -c "ipa-diagnose --version | grep -q ipa-diagnose"

step "5. First real run on a non-FreeIPA host (must degrade gracefully, not crash)"
ipa-diagnose diagnose || true
check "runs without crashing when ipa-healthcheck is absent" bash -c "ipa-diagnose diagnose >/dev/null 2>&1; test \$? -le 3"

if [ -d /fixtures/replication/healthy ]; then
    step "6. Demo run against a bundled fixture (--replay)"
    ipa-diagnose --replay /fixtures/replication/healthy diagnose
    check "fixture replay run succeeds" ipa-diagnose --replay /fixtures/replication/healthy diagnose --json
fi

if compgen -G "/rpms/v2/*.noarch.rpm" > /dev/null; then
    step "7. Upgrade to a newer build"
    dnf install -y /rpms/v2/*.noarch.rpm
    NEW_VERSION=$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' ipa-diagnose)
    echo "Now installed as: ${NEW_VERSION}"
    check "version actually changed after upgrade" bash -c "[ '${NEW_VERSION}' != '${INSTALLED_VERSION}' ]"
    check "ipa-diagnose still works after upgrade" ipa-diagnose --version
else
    echo "(skipping upgrade test: no /rpms/v2 provided)"
fi

step "8. Uninstall"
dnf remove -y ipa-diagnose
check "rpm no longer reports the package installed" bash -c "! rpm -q ipa-diagnose >/dev/null 2>&1"
check "ipa-diagnose command is gone" bash -c "! command -v ipa-diagnose >/dev/null 2>&1"
check "system python3 is STILL 3.6.8 after uninstall" bash -c "/usr/bin/python3 --version 2>&1 | grep -q '3\\.6\\.8'"

step "9. Reinstall (from scratch, after a clean uninstall)"
dnf install -y /rpms/v1/*.noarch.rpm
check "package reinstalls cleanly" rpm -q ipa-diagnose
check "ipa-diagnose works again after reinstall" ipa-diagnose --version

echo
echo "===================================="
echo "EL8 RPM lifecycle verification: ${PASS} passed, ${FAIL} failed"
echo "===================================="
[ "${FAIL}" -eq 0 ]
