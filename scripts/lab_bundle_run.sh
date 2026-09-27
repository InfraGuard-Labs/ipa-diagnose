#!/bin/bash
# Live-lab support-bundle scenario (used only by the live FreeIPA workflow; runs on the CI runner).
#   scripts/lab_bundle_run.sh SCENARIO_ID TAG USER 'SPEC-JSON'
# Diagnose, snapshot IPA unit states + the saved verify baseline, create a bundle (with canary AI/cloud credentials in
# its environment and an AI provider configured - a bundle must use neither), preview it, snapshot again, diagnose
# again, validate, copy the bundle out, then assert (scripts/lab_bundle.py). Everything lands in out/TAG-*.
set +e
S=$1; TAG=$2; U=${3:-root}; SPEC=${4:-"{}"}
BIN=/root/.local/bin/ipa-diagnose
DIR=/root; [ "$U" = root ] || DIR=/tmp
CANARY_ENV=(-e OPENAI_API_KEY=sk-zqlivecanaryenv9xxxxxxxxxxxxxxxxxxx -e ANTHROPIC_API_KEY=sk-ant-zqlivecanaryenv10xxxxxxxx
            -e AWS_SECRET_ACCESS_KEY=ZQLIVECANARYENV11 -e IPA_DIAGNOSE_AI_PROVIDER=openai)
UNITS="dirsrv@$INST.service krb5kdc.service kadmin.service httpd.service $NAMED certmonger.service pki-tomcatd@pki-tomcat.service ipa-custodia.service sssd.service"
state() {
  docker exec ipa-s sh -c "for u in $UNITS; do echo \"\$u \$(systemctl is-active \$u)\"; done;
    sha256sum /var/lib/ipa-diagnose/*.json /root/.cache/ipa-diagnose/*.json 2>/dev/null; ls -A /root /tmp | grep -v '$TAG' | sort"
}
docker exec -u "$U" ipa-s $BIN --json > "out/$TAG-before.json" 2>/dev/null
state > "out/$TAG-state-before.txt"
/usr/bin/time -f "%e" -o "out/$TAG-bundle-seconds.txt" docker exec -u "$U" "${CANARY_ENV[@]}" ipa-s $BIN bundle --output "$DIR/$TAG.tar.gz" > "out/$TAG-bundle.txt" 2>&1
echo "exit=$?" >> "out/$TAG-bundle.txt"
docker exec -u "$U" "${CANARY_ENV[@]}" ipa-s $BIN bundle --preview > "out/$TAG-preview.txt" 2>&1; echo "exit=$?" >> "out/$TAG-preview.txt"
state > "out/$TAG-state-after.txt"
docker exec -u "$U" ipa-s $BIN --json > "out/$TAG-after.json" 2>/dev/null
docker exec ipa-s stat -c '%a %U' "$DIR/$TAG.tar.gz" > "out/$TAG-mode.txt" 2>&1
docker exec -u nobody ipa-s sh -c "cat '$DIR/$TAG.tar.gz' > /dev/null 2>&1" && echo "readable-by-others" >> "out/$TAG-mode.txt"
docker cp "ipa-s:$DIR/$TAG.tar.gz" "out/$TAG.tar.gz"
docker cp "out/$TAG.tar.gz" ipa-s:/tmp/validate-$TAG.tar.gz; docker exec ipa-s chmod 0644 /tmp/validate-$TAG.tar.gz
docker exec -u nobody ipa-s $BIN bundle validate /tmp/validate-$TAG.tar.gz > "out/$TAG-validate.txt" 2>&1; echo "exit=$?" >> "out/$TAG-validate.txt"
docker exec ipa-s rm -f /tmp/validate-$TAG.tar.gz
python3 scripts/lab_bundle.py check "$S" "out/$TAG.tar.gz" "out/$TAG-before.json" "out/$TAG-after.json" "$SPEC" "$TAG"
head -12 "out/$TAG-bundle.txt"
