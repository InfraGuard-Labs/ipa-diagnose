#!/usr/bin/env bash
# Generic RPM lifecycle verification, run inside a CLEAN matching-distro
# container (ipa-diagnose is not baked in). Mounts expected:
#   /rpms/v1/*.rpm      candidate release "1"        /rpms/v2/*.rpm  release "2" (upgrade test)
#   /rpms/SHA256SUMS    checksums of both            /fixtures       tests/fixtures (read-only)
# Env: EXPECT_VERSION (e.g. 0.1.2)  PLATFORM (label only)
# Prints PASS/FAIL per step; exits non-zero if any step fails.
set -uo pipefail
PASS=0; FAIL=0
step() { echo; echo "=== $* ==="; }
check() { local d="$1"; shift; if "$@"; then echo "PASS: $d"; PASS=$((PASS+1)); else echo "FAIL: $d"; FAIL=$((FAIL+1)); fi; }
. /etc/os-release
echo "Platform label: ${PLATFORM:-?} | ${PRETTY_NAME} | expecting ipa-diagnose ${EXPECT_VERSION}"

step "0. Checksum verification of the exact candidate artifacts"
( cd /rpms && sha256sum -c SHA256SUMS ) ; check "SHA256SUMS verifies" bash -c "cd /rpms && sha256sum -c SHA256SUMS >/dev/null"

step "1. Documented prerequisites (README) for this platform"
case "${VERSION_ID%%.*}" in
  8) dnf install -y --setopt=install_weak_deps=False python3 dnf-plugins-core python39 >/dev/null ;;
  9|10) if [ "${ID}" != "fedora" ]; then dnf install -y epel-release dnf-plugins-core >/dev/null && dnf config-manager --set-enabled crb >/dev/null 2>&1 || true; fi ;;
esac
[ "${ID}" = "fedora" ] && dnf install -y --setopt=install_weak_deps=False dnf-plugins-core >/dev/null || true

step "2. Fresh install from the candidate RPM (dnf install ./file)"
dnf install -y /rpms/v1/*.noarch.rpm
check "package registered" rpm -q ipa-diagnose
check "ipa-diagnose on PATH" bash -c "command -v ipa-diagnose"
rpm -qR ipa-diagnose | sed 's/^/  requires: /'
check "--version reports ${EXPECT_VERSION}" bash -c "ipa-diagnose --version | grep -q 'ipa-diagnose ${EXPECT_VERSION}\$'"
ipa-diagnose --version
check "--help works" bash -c "ipa-diagnose --help | grep -q verify"

step "3. Replay: healthy fixture -> HEALTHY, fully verified"
ipa-diagnose --replay /fixtures/replication/healthy --details; rc=$?; echo "exit=${rc}"
check "healthy replay exits 0" test "${rc}" -eq 0
check "healthy replay says HEALTHY" bash -c "ipa-diagnose --replay /fixtures/replication/healthy | grep -q 'Overall: HEALTHY'"

step "4. Replay: REAL captured stopped-Directory-Server evidence -> CRITICAL primary"
ipa-diagnose --replay /fixtures/real-freeipa-capture/dirsrv-stopped --details; rc=$?; echo "exit=${rc}"
check "dirsrv-stopped replay exits 2 (CRITICAL)" test "${rc}" -eq 2
check "names the stopped service" bash -c "ipa-diagnose --replay /fixtures/real-freeipa-capture/dirsrv-stopped | grep -q \"'dirsrv' is not running\""

step "5. --json exposes evidence completeness"
ipa-diagnose --replay /fixtures/replication/healthy --json > /tmp/j.json; python3 - <<'PY'
import json
d = json.load(open("/tmp/j.json"))
print({k: d[k] for k in ("overall_status", "fully_verified")}, d["evidence_completeness"]["level"])
assert "evidence_completeness" in d and "fully_verified" in d
PY
check "json has evidence_completeness + fully_verified" test $? -eq 0

step "6. Non-FreeIPA host (no ipa-healthcheck): must be UNKNOWN (exit 3), never HEALTHY"
ipa-diagnose --details; rc=$?; echo "exit=${rc}"
check "no-healthcheck host exits 3 (UNKNOWN)" test "${rc}" -eq 3
check "output says UNKNOWN and why" bash -c "ipa-diagnose | grep -q 'Overall: UNKNOWN' && ipa-diagnose | grep -q 'could not be collected'"
check "never claims healthy" bash -c "! ipa-diagnose | grep -q 'Overall: HEALTHY'"
ipa-diagnose --json > /tmp/j2.json 2>/dev/null
python3 -c "import json; d=json.load(open('/tmp/j2.json')); assert d['overall_status']=='UNKNOWN' and d['fully_verified'] is False and d['evidence_completeness']['level']=='insufficient'"
check "json: UNKNOWN / fully_verified false / insufficient" test $? -eq 0

step "7. Uninstall, verify removal"
dnf remove -y ipa-diagnose
check "package removed" bash -c "! rpm -q ipa-diagnose >/dev/null 2>&1"
check "command removed" bash -c "! command -v ipa-diagnose >/dev/null 2>&1"

step "8. Reinstall"
dnf install -y /rpms/v1/*.noarch.rpm
check "reinstall works" ipa-diagnose --version

step "9. Upgrade to release 2"
V1=$(rpm -q --qf '%{VERSION}-%{RELEASE}' ipa-diagnose)
dnf install -y /rpms/v2/*.noarch.rpm
V2=$(rpm -q --qf '%{VERSION}-%{RELEASE}' ipa-diagnose)
echo "upgraded ${V1} -> ${V2}"
check "version-release changed on upgrade" test "${V1}" != "${V2}"
check "still works after upgrade" bash -c "ipa-diagnose --version | grep -q ${EXPECT_VERSION}"

step "10. Final uninstall"
dnf remove -y ipa-diagnose
check "final removal clean" bash -c "! rpm -q ipa-diagnose >/dev/null 2>&1"

echo; echo "===================================="; echo "RPM lifecycle (${PLATFORM:-?}): ${PASS} passed, ${FAIL} failed"; echo "===================================="
[ "${FAIL}" -eq 0 ]
