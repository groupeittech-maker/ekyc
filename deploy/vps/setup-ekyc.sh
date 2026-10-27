#!/usr/bin/env bash
# Bootstrap eKYC (Trusdy) on the dedicated VPS — srv1992558.hstgr.cloud.
# Idempotent: safe to re-run. Expects the source tree already extracted at
# /var/www/ekyc and .env written by the local deploy driver.
set -euo pipefail

APP_DIR=/var/www/ekyc
DOMAIN=ekyc.srv1992558.hstgr.cloud
cd "$APP_DIR"

echo "== 1. Docker =="
if ! command -v docker >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl
    curl -fsSL https://get.docker.com | sh
fi
docker --version

echo "== 2. Build & start stack =="
docker compose -p ekyc \
    -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.vps.yml \
    up -d --build

echo "== 3. Biometric models (one-shot fetchers) =="
docker compose -p ekyc -f docker-compose.yml run --rm models-init
docker compose -p ekyc -f docker-compose.yml run --rm antispoof-init || true

echo "== 4. Signing key material =="
# Self-signed platform key generated on host, injected into the archive
# volume. In real production replace with a CA/HSM-backed certificate.
KEYDIR=$(docker volume inspect ekyc_archive --format '{{.Mountpoint}}')/keys
mkdir -p "$KEYDIR/csca"
if [ ! -f "$KEYDIR/signing_key.pem" ]; then
    openssl req -x509 -newkey rsa:4096 -nodes \
        -keyout "$KEYDIR/signing_key.pem" \
        -out "$KEYDIR/signing_cert.pem" \
        -days 1825 -subj "/C=CI/O=IT-TECH/OU=Trusdy/CN=ekyc-signing"
    chmod 600 "$KEYDIR/signing_key.pem"
fi
ls -l "$KEYDIR"

echo "== 5. nginx + TLS =="
apt-get install -y -qq nginx certbot python3-certbot-nginx >/dev/null 2>&1 || true
cp deploy/vps/nginx-ekyc.conf /etc/nginx/sites-available/ekyc.conf
ln -sf /etc/nginx/sites-available/ekyc.conf /etc/nginx/sites-enabled/ekyc.conf
nginx -t && systemctl reload nginx
certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos \
    --register-unsafely-without-email --redirect || true
systemctl reload nginx

echo "== 6. Health =="
sleep 3
curl -sf http://127.0.0.1:8300/health || echo "API not answering yet — check: docker compose -p ekyc logs api"
docker compose -p ekyc ps
