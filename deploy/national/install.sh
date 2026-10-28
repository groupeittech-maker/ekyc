#!/usr/bin/env bash
# Trusdy National — idempotent installer.
#   bash install.sh --domain ekyc.example.tld --profile country-profiles/CI.json
# Re-runnable: existing secrets are never regenerated, the stack converges.
set -euo pipefail

APP_DIR="${APP_DIR:-/var/www/ekyc}"
PROJECT="ekyc"   # fixed → volume ekyc_archive is deterministic
DOMAIN=""
PROFILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --domain)  DOMAIN="$2"; shift 2 ;;
        --profile) PROFILE="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done
[ -n "$DOMAIN" ]  || { echo "--domain required" >&2; exit 1; }
[ -n "$PROFILE" ] || { echo "--profile <country-profiles/XX.json> required" >&2; exit 1; }

cd "$APP_DIR"
COMPOSE="docker compose -p $PROJECT -f deploy/national/docker-compose.national.yml --env-file .env"
gen()  { python3 -c "import secrets; print(secrets.token_urlsafe(${1:-48}))"; }

echo "== 1. Prerequisites =="
command -v docker >/dev/null || { curl -fsSL https://get.docker.com | sh; }
docker compose version >/dev/null
command -v openssl >/dev/null

echo "== 2. Secrets (.env preserved when present) =="
if [ ! -f .env ]; then
    cp deploy/national/.env.national.example .env
    PGP=$(gen 32)
    sed -i "s|ekyc.EXAMPLE.tld|${DOMAIN}|" .env
    sed -i "s|POSTGRES_PASSWORD=__GENERATED__|POSTGRES_PASSWORD=${PGP}|" .env
    sed -i "s|ekyc:__GENERATED__@|ekyc:${PGP}@|" .env
    sed -i "0,/EKYC_ADMIN_API_KEY=__GENERATED__/s|__GENERATED__|$(gen 48)|" .env
    sed -i "0,/EKYC_JWT_SECRET=__GENERATED__/s|__GENERATED__|$(gen 48)|" .env
    sed -i "s|__GENERATED_64HEX__|$(python3 -c 'import secrets; print(secrets.token_hex(32))')|" .env
    chmod 600 .env
    echo "  .env created (secrets generated, chmod 600)"
else
    echo "  .env exists — untouched"
fi
sed -i "s|EKYC_BASE_URL=.*|EKYC_BASE_URL=https://${DOMAIN}|" .env

echo "== 3. Country profile =="
python3 -m scripts.validate_profile "$PROFILE"
COUNTRY=$(basename "$PROFILE" .json)
KEYDIR="$(docker volume inspect ${PROJECT}_archive --format '{{.Mountpoint}}' 2>/dev/null || true)"
[ -z "$KEYDIR" ] && { docker volume create ${PROJECT}_archive >/dev/null; \
    KEYDIR=$(docker volume inspect ${PROJECT}_archive --format '{{.Mountpoint}}'); }
mkdir -p "$KEYDIR/country-profiles" "$KEYDIR/keys/csca"
cp "$PROFILE" "$KEYDIR/country-profiles/${COUNTRY}.json"
grep -q '^EKYC_COUNTRY_PROFILE=' .env \
    && sed -i "s|EKYC_COUNTRY_PROFILE=.*|EKYC_COUNTRY_PROFILE=/srv/ekyc/var/country-profiles/${COUNTRY}.json|" .env \
    || echo "EKYC_COUNTRY_PROFILE=/srv/ekyc/var/country-profiles/${COUNTRY}.json" >> .env

echo "== 4. Signing key material =="
if [ ! -f "$KEYDIR/keys/signing_key.pem" ]; then
    openssl req -x509 -newkey rsa:4096 -nodes \
        -keyout "$KEYDIR/keys/signing_key.pem" \
        -out "$KEYDIR/keys/signing_cert.pem" \
        -days 1825 -subj "/O=Trusdy/CN=ekyc-signing"
    chmod 600 "$KEYDIR/keys/signing_key.pem"
fi

echo "== 5. Stack =="
$COMPOSE up -d --build
$COMPOSE run --rm models-init
$COMPOSE run --rm antispoof-init || true

echo "== 6. CSCA master list =="
docker run --rm -v ${PROJECT}_archive:/srv/ekyc/var -v "$APP_DIR":/src -w /src \
    ${PROJECT}-api python -m scripts.fetch_csca || true

echo "== 7. Health check =="
sleep 10
EKYC_LOCAL_PORT=8300 bash deploy/national/health-check.sh "$DOMAIN"
