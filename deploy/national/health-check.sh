#!/usr/bin/env bash
# Trusdy National — post-install health checks.
#   bash health-check.sh [domain]
# Exit 0 = all mandatory checks pass. Read-only; safe to run anytime.
set -uo pipefail

DOMAIN="${1:-}"
LOCAL="http://127.0.0.1:${EKYC_LOCAL_PORT:-8300}"
PASS=0; FAIL=0

ok()   { echo "  ✓ $1"; PASS=$((PASS+1)); }
bad()  { echo "  ✗ $1"; FAIL=$((FAIL+1)); }

echo "== Containers =="
for c in api worker-cpu worker-gpu beat postgres redis; do
    docker ps --format '{{.Names}}' | grep -q "ekyc-$c-1" && ok "$c running" || bad "$c not running"
done

echo "== API =="
BODY=$(curl -sf "$LOCAL/health" 2>/dev/null) && ok "/health reachable: $BODY" || bad "API /health unreachable"

echo "== Secrets hygiene =="
ENVF="${APP_DIR:-/var/www/ekyc}/.env"
[ -f "$ENVF" ] || { bad ".env missing"; exit 1; }
for k in EKYC_ADMIN_API_KEY EKYC_JWT_SECRET EKYC_KEK; do
    V=$(grep "^$k=" "$ENVF" | cut -d= -f2)
    [ ${#V} -ge 32 ] && ok "$k strength (${#V} chars)" || bad "$k too short"
done
grep -q '^EKYC_ENVIRONMENT=production' "$ENVF" && ok "environment=production" || bad "environment != production"
grep -q 'stub\|EKYC_OTP_PROVIDER=log' "$ENVF" && bad "dev provider present" || ok "no dev providers"

echo "== Encryption & keys =="
grep -q '^EKYC_STORAGE_ENCRYPTION=true' "$ENVF" && ok "storage encryption on" || bad "storage encryption off"
KEYDIR=$(docker volume inspect ekyc_archive --format '{{.Mountpoint}}' 2>/dev/null || true)
[ -n "$KEYDIR" ] && [ -f "$KEYDIR/keys/signing_key.pem" ] && ok "signing key present" || bad "signing key missing"
[ -n "$KEYDIR" ] && [ -s "$KEYDIR/keys/csca/"*.pem ] 2>/dev/null && ok "CSCA store populated" || bad "CSCA store empty"

echo "== Models =="
MODELDIR=$(docker volume inspect ekyc_models --format '{{.Mountpoint}}' 2>/dev/null || true)
[ -n "$MODELDIR" ] && [ -f "$MODELDIR/antispoof_quantized.onnx" ] && ok "antispoof model" || bad "antispoof model missing"

echo "== Country profile gate =="
grep -q '^EKYC_REQUIRE_COUNTRY_PROFILE=true' "$ENVF" && ok "profile gate mandatory" || bad "profile gate optional"

echo "== Database =="
docker exec ekyc-postgres-1 pg_isready -U ekyc -q 2>/dev/null && ok "postgres ready" || bad "postgres not ready"
docker exec ekyc-redis-1 redis-cli ping >/dev/null 2>&1 && ok "redis PING" || bad "redis dead"

if [ -n "$DOMAIN" ]; then
    echo "== Public TLS =="
    curl -sf "https://$DOMAIN/health" >/dev/null 2>&1 && ok "https://$DOMAIN/health" || bad "public health check failed"
fi

echo
echo "== $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
