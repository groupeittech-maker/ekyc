# IT-TECH eKYC — Plateforme de confiance numérique

Plateforme indépendante et multi-tenant d'identité, de biométrie et de preuve électronique.
MHC (Mobility Healthcare) est le premier client : il consomme l'API, il n'héberge aucune logique eKYC.

```
MHC / Banque / Fintech / Administration
                │  API HTTPS + OAuth2 (client_credentials)
                ▼
        IT-TECH eKYC
   Identity · Document · Biometrics · Liveness · OTP
   Signature · Timestamp · SHA-256 · Audit · Archive
```

Voir [ARCHITECTURE.md](ARCHITECTURE.md) pour le détail des moteurs, du modèle de données et des
décisions d'architecture.

## Principe d'intégration

Le client ne pilote pas les étapes. Il crée une session et reçoit un résultat abstrait :

```bash
POST /v1/kyc/sessions
{"customer_reference": "MHC-123456", "flow": "TRAVEL_INSURANCE"}

→ {"session_id": "KYC-2026-0000A1B2", "status": "CREATED", "verification_url": "https://…/verify/KYC-…?token=…"}
```

Le client ouvre la `verification_url` (UI hébergée par l'eKYC), puis récupère le résultat par
webhook signé et/ou `GET /v1/kyc/sessions/{session_id}` :

```json
{
  "session_id": "KYC-2026-0000A1B2",
  "status": "VERIFIED",
  "identity": {"first_name": "John", "last_name": "DOE", "date_of_birth": "1990-05-15"},
  "checks": {"document": "PASSED", "liveness": "PASSED", "face_match": "PASSED", "otp": "PASSED"}
}
```

Les scores bruts, images, selfies et payloads fournisseurs ne sortent jamais de la plateforme.

## Démarrage rapide

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
uvicorn app.main:app --reload
```

Documentation interactive : http://localhost:8000/docs — santé : `GET /health`.

Avec Docker (PostgreSQL, Redis, MinIO, API, worker Celery) :

```bash
cp .env.example .env
docker compose up --build
```

En développement (`EKYC_ENVIRONMENT=development`) les tables sont créées au démarrage.
En production, appliquer les migrations : `alembic upgrade head`.

## Parcours complet en API

```bash
# 1. Créer un tenant (API d'administration)
curl -X POST localhost:8000/v1/admin/tenants -H "X-Admin-Key: $EKYC_ADMIN_API_KEY" \
  -H 'content-type: application/json' \
  -d '{"name":"MHC","allowed_flows":["TRAVEL_INSURANCE"],"webhook_url":"https://mhc.example/webhooks/kyc"}'
# → client_id / client_secret / webhook_secret : affichés une seule fois

# 2. Jeton tenant
curl -X POST localhost:8000/v1/oauth/token -H 'content-type: application/json' \
  -d '{"grant_type":"client_credentials","client_id":"…","client_secret":"…"}'

# 3. Session KYC
curl -X POST localhost:8000/v1/kyc/sessions -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"customer_reference":"MHC-123456","flow":"TRAVEL_INSURANCE"}'

# 4. L'utilisateur suit la verification_url, puis :
curl localhost:8000/v1/kyc/sessions/KYC-… -H "authorization: Bearer $TOKEN"
```

### Endpoints principaux

| Endpoint | Usage |
| --- | --- |
| `POST /v1/admin/tenants` | Créer un tenant (`X-Admin-Key`) |
| `POST /v1/oauth/token` | Jeton tenant (`client_credentials`) |
| `POST /v1/kyc/sessions` | Créer une session, obtenir la `verification_url` |
| `GET /v1/kyc/sessions/{id}` | Résultat minimisé (statut, checks, identité utile) |
| `GET /v1/kyc/sessions/{id}/audit` | Export de la piste d'audit chaînée + vérification |
| `GET /v1/kyc/sessions/{id}/certificate` | Certificat KYC PDF signé et horodaté |
| `POST /v1/kyc/sessions/{id}/documents` | Sceller un contrat client : SHA-256 + signature + TSA + archivage |
| `GET /v1/kyc/sessions/{id}/documents/{doc_id}` | Télécharger le document scellé |
| `GET /verify/{id}?token=…` | UI de vérification hébergée (utilisateur final) |
| `/v1/verification/{id}/…` | API de l'UI hébergée (jeton de session, portée : une session) |

## Webhooks

Chaque changement d'état terminal déclenche un `POST` vers le `webhook_url` du tenant :

```json
{"event": "KYC_VERIFIED", "session_id": "KYC-…", "customer_reference": "MHC-123456", "status": "VERIFIED"}
```

Signature : `X-EKYC-Signature: sha256=<HMAC(webhook_secret, timestamp + "." + body)>`
avec `X-EKYC-Timestamp`. Les livraisons sont rejouables et tracées en base.

## Flows (Policy Engine)

| Flow | Documents | Étapes |
| --- | --- | --- |
| `TRAVEL_INSURANCE` | Passeport | OCR, document, selfie, liveness, face match, OTP, signature |
| `BANK_ACCOUNT` | CNI, passeport | OCR, document, selfie, liveness, face match, OTP, signature |
| `CITIZEN` | CNI, titre de séjour | OCR, document, OTP |

Un échec de liveness est bloquant (`REJECTED`) ; un échec de face match part en `REVIEW`.
Ajouter un vertical = ajouter une policy, pas de code client.

## Tests, lint

```bash
pytest -q
ruff check . && ruff format --check .
```

Les providers `stub` sont déterministes : inclure `LIVENESS_FAIL`, `FACE_MATCH_FAIL` ou `DOC_FAIL`
dans les octets envoyés permet de tester les branches d'échec.

## Production — points d'attention

- Fournir `EKYC_ADMIN_API_KEY` et `EKYC_JWT_SECRET` (jamais les valeurs par défaut).
- Clé de signature gérée par HSM/KMS ; la clé RSA auto-générée est réservée au développement.
- Configurer `EKYC_TSA_URL` (RFC 3161) : sans TSA, l'horodatage local est marqué `qualified: false`.
- `EKYC_CELERY_ALWAYS_EAGER=false` pour sortir OCR/biométrie/PDF du cycle HTTP.
- Stockage objet chiffré (`EKYC_STORAGE_BACKEND=s3`), rétention par tenant.
- Brancher de vrais providers OCR/biométrie (`EKYC_OCR_PROVIDER`, `EKYC_FACE_PROVIDER`).
