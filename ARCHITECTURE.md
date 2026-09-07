# Architecture — IT-TECH eKYC

## 1. Positionnement

L'eKYC n'est pas un module de MHC : c'est une plateforme de confiance numérique autonome, dont MHC
est le tenant n°1. Toute la logique d'identité, de biométrie et de preuve vit ici ; le client ne
voit qu'une session et un verdict.

```
        Tenant (MHC, banque, fintech, hôpital, administration)
                 │ OAuth2 client_credentials
                 ▼
   ┌──────────────────────────────────────────────┐
   │ API eKYC (FastAPI)                            │
   │   /v1/oauth  /v1/kyc/sessions  /v1/admin      │
   │   /v1/verification (UI hébergée)              │
   ├──────────────────────────────────────────────┤
   │ Policy Engine → Decision Engine               │
   │ Identity · Biometrics · OTP · Evidence        │
   ├──────────────────────────────────────────────┤
   │ Audit Engine (chaîne de hachage)              │
   ├───────────────┬───────────────┬──────────────┤
   │ PostgreSQL    │ Redis+Celery  │ Object store │
   └───────────────┴───────────────┴──────────────┘
```

## 2. Objet central : la KYC Session

`KycSession` (`app/models/session.py`) porte l'identifiant `KYC-<année>-<suffixe>`, le tenant, la
`customer_reference` du client, le flow, le statut, les checks, l'identité consolidée et un bloc
`internal` (scores, payloads providers) qui n'est jamais exposé.

Statuts : `CREATED → IN_PROGRESS → PROCESSING → VERIFIED | REJECTED | REVIEW`, plus `EXPIRED`.

Le client crée la session et reçoit une `verification_url`. L'utilisateur final quitte
temporairement l'application du client, effectue les étapes dans l'UI eKYC, puis revient.
L'UI n'utilise jamais le jeton du tenant : elle porte un jeton de session, limité à une session et
à ses étapes.

## 3. Moteurs

| Moteur | Fichier | Rôle |
| --- | --- | --- |
| Policy | `app/engines/policy.py` | Documents acceptés, étapes requises, sévérité des échecs |
| Identity | `app/engines/identity.py` | OCR → authenticité → expiration → identité structurée |
| Biometrics | `app/engines/biometrics.py` | Liveness d'abord, puis face matching |
| OTP | `app/engines/otp.py` | Envoi/vérification, code haché, jamais exposé |
| Decision | `app/engines/decision.py` | Agrège les checks en `VERIFIED / REJECTED / REVIEW` |
| Audit | `app/engines/audit.py` | Journal append-only chaîné |
| Signature | `app/engines/signature.py` | RSASSA-PKCS1-v1_5-SHA256 sur l'empreinte |
| Timestamp | `app/engines/timestamp.py` | RFC 3161 (TSA) ou fallback local marqué non qualifié |

La distinction demandée est respectée dans le modèle : OCR (« je lis »), document verification
(« le document semble authentique ») et identity verification (« les informations correspondent à
la personne ») sont trois checks séparés, comme liveness et face match.

Les providers sont pluggables (`app/engines/providers/`) : `stub` déterministe pour le
développement, MRZ TD3 réel avec chiffres de contrôle, Tesseract optionnel, sender OTP HTTP.
Brancher un fournisseur commercial revient à implémenter l'interface de `providers/base.py`.

## 4. Chaîne de preuve

`app/services/evidence.py` exécute pour chaque document :

```
PDF → stockage → SHA-256 → signature serveur → horodatage → métadonnées de preuve → archivage
        │           │            │                 │                                    │
        └───────────┴────────────┴─────────────────┴───── un événement d'audit à chaque étape
```

Le SHA-256 prouve l'intégrité, il ne chiffre pas. Le token d'horodatage est archivé comme artefact
distinct. Sans TSA configurée, la réponse porte `qualified: false` et
`warning: NOT_A_QUALIFIED_TSA_TOKEN` — la valeur probatoire n'est pas surestimée.

## 5. Audit immuable

Chaque événement est numéroté par session et haché avec le hash précédent :

```
event_hash = SHA256(sequence ‖ type ‖ session ‖ tenant ‖ acteur ‖ horodatage ‖ payload ‖ document_hash ‖ previous_event_hash)
```

`GET /v1/kyc/sessions/{id}/audit` réexécute le calcul et renvoie la validité de la chaîne ainsi que
le hash de tête. Toute altération d'un événement passé casse la vérification.

## 6. Multi-tenant

Le `tenant_id` est porté par toutes les tables métier et injecté dans toutes les requêtes via les
dépendances d'authentification (`app/api/deps.py`), donc aucune fuite entre clients. Les clés de
stockage sont namespacées :

```
tenant/<tenant_id>/<YYYY>/<MM>/<DD>/<session_id>/<kind>/<filename>
```

Chaque tenant a ses credentials, son secret webhook, ses flows autorisés, son branding et sa
politique de rétention. Les secrets ne sont retournés qu'à la création ; seuls des hachés sont
stockés.

## 7. Minimisation des données

Le client reçoit le strict nécessaire : statut, checks métier, identité utile, KYC ID et, à la
demande, le document scellé. Images, selfies, scores bruts et réponses des fournisseurs restent
internes. `public_result()` (`app/services/kyc.py`) est le seul point de sortie.

## 8. Traitements asynchrones

OCR, biométrie, génération PDF, signature, archivage et webhooks sont des tâches Celery
(`app/workers/`) sur Redis, avec files dédiées. En développement et dans les tests,
`EKYC_CELERY_ALWAYS_EAGER=true` les exécute en ligne pour garder le parcours reproductible ; en
production ces traitements sortent du cycle HTTP et l'API répond `202`.

## 9. Suite du produit

La même base porte les briques suivantes : e-signature autonome (signature de documents hors
parcours KYC), vérification externe d'un document par son empreinte, portail tenant et console
d'audit, connecteurs registres d'état civil, rétention/purge automatiques, certification eIDAS avec
une TSA et un HSM qualifiés.
