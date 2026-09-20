#!/usr/bin/env bash
# Semantics check of the DISTRIBUTED package (run inside a clean container after
# `dnf install` of the published RPM, hostname ipa01.example.test).
# The live-path cases put tiny stand-in tools first on PATH that print the real
# output SHAPES of ipa-healthcheck / ipa-replica-manage; they test ipa-diagnose's
# evidence-completeness semantics, not FreeIPA itself.
set -uo pipefail
PASS=0; FAIL=0
expect() { # desc, expected_exit, expected_text, actual_exit, output
  local ok=1
  [ "$4" -eq "$2" ] || ok=0
  echo "$5" | grep -q "$3" || ok=0
  if [ $ok -eq 1 ]; then echo "PASS: $1 (exit $4, '$3')"; PASS=$((PASS+1)); else echo "FAIL: $1 (exit $4, wanted $2 + '$3')"; echo "$5" | head -20; FAIL=$((FAIL+1)); fi
}

# 1. ipa-healthcheck unavailable -> UNKNOWN, exit 3
out=$(ipa-diagnose 2>&1); rc=$?
expect "healthcheck unavailable => UNKNOWN" 3 "Overall: UNKNOWN" "$rc" "$out"

# 2. healthy replay fixture -> HEALTHY, exit 0 (fixture mode)
out=$(ipa-diagnose --replay /fixtures/replication/healthy 2>&1); rc=$?
expect "healthy replay => HEALTHY" 0 "Overall: HEALTHY" "$rc" "$out"

BIN=$(mktemp -d)
cat > "$BIN/ipa-healthcheck" <<'EOF'
#!/bin/sh
cat <<'JSON'
[{"source":"ipahealthcheck.meta.services","check":"dirsrv","result":"SUCCESS","uuid":"11111111-1111-1111-1111-111111111111","when":"20260101000000Z","duration":"0.01","kw":{"status":true}}]
JSON
EOF
chmod +x "$BIN/ipa-healthcheck"

# 3. partial evidence: healthcheck fine, replication tooling unavailable -> NOT_FULLY_VERIFIED, exit 4
out=$(PATH="$BIN:$PATH" ipa-diagnose 2>&1); rc=$?
expect "partial evidence => NOT_FULLY_VERIFIED" 4 "Overall: NOT_FULLY_VERIFIED" "$rc" "$out"

# 4. RUV unreadable (list-ruv wants the Directory Manager password) -> NOT_FULLY_VERIFIED + explicit RUV state
cat > "$BIN/ipa-replica-manage" <<'EOF'
#!/bin/sh
echo "Directory Manager password required" >&2
exit 1
EOF
chmod +x "$BIN/ipa-replica-manage"
out=$(PATH="$BIN:$PATH" ipa-diagnose 2>&1); rc=$?
expect "RUV unreadable => RUV NOT VERIFIED" 4 "RUV state: NOT VERIFIED" "$rc" "$out"

# 5. fully verified healthy (live path): tools succeed, RUV readable and every replica accounted for -> HEALTHY
cat > "$BIN/ipa-replica-manage" <<'EOF'
#!/bin/sh
case "$1" in
  list-ruv) printf 'Replica Update Vectors:\nipa01.example.test:389: 4\n' ;;
  list) : ;;
esac
exit 0
EOF
out=$(PATH="$BIN:$PATH" ipa-diagnose 2>&1); rc=$?
expect "fully verified healthy => HEALTHY" 0 "Overall: HEALTHY" "$rc" "$out"

echo "SEMANTICS: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
