#!/usr/bin/env bash
# Tests d'intégration end-to-end IronShield FIM.
# Vérifie le flux complet: activation -> envoi d'événements -> lecture des alertes.
#
# Requiert: curl, jq, une base de test avec au moins une licence valide.
# Usage:
#   E2E_API_BASE=https://wiseshield.alwaysdata.net/api \
#   E2E_LICENSE_KEY=ABCDE-FGHJK-LMNPQ-RSTUV-WXY23 \
#   ./tests/e2e.sh

set -euo pipefail

API_BASE="${E2E_API_BASE:-http://localhost:8080/api}"
LICENSE_KEY="${E2E_LICENSE_KEY:?Variable E2E_LICENSE_KEY requise}"
HARDWARE_ID=$(printf '%s' "e2e-test-$(date +%s)" | sha256sum | cut -d' ' -f1)

pass=0
fail=0

check() {
    local desc="$1" cond="$2"
    if [ "$cond" = "true" ]; then
        echo "  ✓ $desc"
        pass=$((pass + 1))
    else
        echo "  ✗ $desc"
        fail=$((fail + 1))
    fi
}

echo "== 1. Activation d'une machine =="
activate_resp=$(curl -s -X POST "${API_BASE}/activate" \
    -H "Content-Type: application/json" \
    -d "{\"license_key\":\"${LICENSE_KEY}\",\"hardware_id\":\"${HARDWARE_ID}\",\"hostname\":\"e2e-runner\",\"os_version\":\"windows-11\",\"agent_version\":\"0.1.0\"}")

valid=$(echo "$activate_resp" | jq -r '.valid // false')
token=$(echo "$activate_resp" | jq -r '.token // empty')

check "réponse valid=true" "$([ "$valid" = "true" ] && echo true || echo false)"
check "token présent (64 hex)" "$(echo "$token" | grep -Eq '^[a-f0-9]{64}$' && echo true || echo false)"

if [ -z "$token" ]; then
    echo "Échec critique: pas de token, arrêt des tests."
    exit 1
fi

echo ""
echo "== 2. Ré-activation idempotente (même hardware_id) =="
reactivate_resp=$(curl -s -X POST "${API_BASE}/activate" \
    -H "Content-Type: application/json" \
    -d "{\"license_key\":\"${LICENSE_KEY}\",\"hardware_id\":\"${HARDWARE_ID}\",\"hostname\":\"e2e-runner\",\"os_version\":\"windows-11\",\"agent_version\":\"0.1.1\"}")
token2=$(echo "$reactivate_resp" | jq -r '.token // empty')
check "même token retourné" "$([ "$token" = "$token2" ] && echo true || echo false)"

echo ""
echo "== 3. Envoi d'un lot d'événements =="
now=$(date +%s)
events_resp=$(curl -s -X POST "${API_BASE}/events" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${token}" \
    -d "{\"events\":[
        {\"path\":\"C:\\\\Windows\\\\System32\\\\drivers\\\\test.sys\",\"event_type\":\"modified\",\"sha256\":\"$(printf 'a%.0s' {1..64})\",\"severity\":\"critical\",\"timestamp\":${now}},
        {\"path\":\"C:\\\\temp\\\\note.txt\",\"event_type\":\"created\",\"severity\":\"info\",\"timestamp\":${now}}
    ]}")

received=$(echo "$events_resp" | jq -r '.received // 0')
check "2 événements reçus" "$([ "$received" = "2" ] && echo true || echo false)"

echo ""
echo "== 4. Rejet sans authentification =="
unauth_status=$(curl -s -o /dev/null -w "%{http_code}" "${API_BASE}/events" -X POST -d '{"events":[]}')
check "HTTP 401 sans token" "$([ "$unauth_status" = "401" ] && echo true || echo false)"

echo ""
echo "== 5. Lecture des alertes (l'événement critique doit avoir généré une alerte) =="
sleep 1
alerts_resp=$(curl -s "${API_BASE}/alerts?limit=10" -H "Authorization: Bearer ${token}")
alert_count=$(echo "$alerts_resp" | jq '.alerts | length')
check "au moins 1 alerte présente" "$([ "$alert_count" -ge 1 ] && echo true || echo false)"

first_severity=$(echo "$alerts_resp" | jq -r '.alerts[0].severity // empty')
check "sévérité critique sur la 1ère alerte" "$([ "$first_severity" = "critical" ] && echo true || echo false)"

echo ""
echo "== 6. Clé de licence invalide rejetée =="
invalid_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${API_BASE}/activate" \
    -H "Content-Type: application/json" \
    -d '{"license_key":"XXXXX-XXXXX-XXXXX-XXXXX-XXXXX","hardware_id":"'"$(printf 'b%.0s' {1..64})"'"}')
check "HTTP 404 sur licence inconnue" "$([ "$invalid_status" = "404" ] && echo true || echo false)"

echo ""
echo "=================================="
echo "Résultats: ${pass} réussis, ${fail} échoués"
echo "=================================="
[ "$fail" -eq 0 ]
