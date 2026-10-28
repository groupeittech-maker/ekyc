#!/usr/bin/env bash
# Enroll this national instance with Trusdy Central.
#   bash enroll.sh --central https://central.example.tld --bootstrap KEY --country CI
#
# Generates the instance Ed25519 keypair (private key never leaves the
# archive volume), registers the public key, and writes
# EKYC_CENTRAL_PUBLIC_KEY + EKYC_INSTANCE_ID into .env.
# The activation attestation itself is issued by the Central operator
# (contract §3.2) — this script only prepares the enrolment side.
set -euo pipefail

CENTRAL=""
BOOT=""
COUNTRY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --central)   CENTRAL="$2"; shift 2 ;;
        --bootstrap) BOOT="$2"; shift 2 ;;
        --country)   COUNTRY="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done
[ -n "$CENTRAL" ] && [ -n "$BOOT" ] && [ -n "$COUNTRY" ] || {
    echo "--central --bootstrap --country required" >&2; exit 1; }

KEYDIR="$(docker volume inspect ekyc_archive --format '{{.Mountpoint}}')"
mkdir -p "$KEYDIR/keys"

docker run --rm -v ekyc_archive:/srv/ekyc/var -e CENTRAL="$CENTRAL" \
    -e BOOT="$BOOT" -e COUNTRY="$COUNTRY" \
    ekyc-api python - <<'PY'
import base64, json, os, urllib.request
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat, load_pem_private_key,
)

keypath = Path("/srv/ekyc/var/keys/instance_ed25519.pem")
key = load_pem_private_key(keypath.read_bytes(), None) if keypath.exists() \
    else Ed25519PrivateKey.generate()
if not keypath.exists():
    keypath.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    keypath.chmod(0o600)

pub = base64.b64encode(
    key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
).decode()
req = urllib.request.Request(
    f"{os.environ['CENTRAL'].rstrip('/')}/v1/instances",
    data=json.dumps({
        "instance_public_key": pub,
        "country_code": os.environ["COUNTRY"],
        "software_version": "0.1.0",
        "capabilities": ["ocr", "mrz", "nfc", "face_match", "liveness"],
    }).encode(),
    headers={"X-Bootstrap-Key": os.environ["BOOT"], "Content-Type": "application/json"},
)
resp = json.loads(urllib.request.urlopen(req).read())
Path("/srv/ekyc/var/keys/instance_enrollment.json").write_text(json.dumps(resp, indent=2))
print("enrolled:", resp["instance_id"])
PY

INSTANCE_ID=$(python3 -c "import json; print(json.load(open('$KEYDIR/keys/instance_enrollment.json'))['instance_id'])")
CENTRAL_PUB=$(python3 -c "import json; print(json.load(open('$KEYDIR/keys/instance_enrollment.json'))['central_public_key'])")

ENVF="${APP_DIR:-/var/www/ekyc}/.env"
for kv in "EKYC_CENTRAL_URL=$CENTRAL" "EKYC_INSTANCE_ID=$INSTANCE_ID" "EKYC_CENTRAL_PUBLIC_KEY=$CENTRAL_PUB" "EKYC_INSTANCE_KEY_PATH=/srv/ekyc/var/keys/instance_ed25519.pem"; do
    k="${kv%%=*}"
    grep -q "^$k=" "$ENVF" && sed -i "s|^$k=.*|$kv|" "$ENVF" || echo "$kv" >> "$ENVF"
done
echo "== Enrolled: $INSTANCE_ID — recreate api/workers to activate heartbeat =="
