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
| Signature | `app/engines/signature_manager.py` | Registre de signataires (`platform` = RSA local ; un DSS/CA externe implémente `Signer`), cycle de vie du certificat (empreinte + expiration dans la preuve) |
| Timestamp | `app/engines/tsa.py` | Registre TSA : interne (soft, non qualifié) ou connecteurs RFC 3161 nommés ; vérification des jetons (imprint, genTime, chaîne si CA de confiance) |

La distinction demandée est respectée dans le modèle : OCR (« je lis »), document verification
(« le document semble authentique ») et identity verification (« les informations correspondent à
la personne ») sont trois checks séparés, comme liveness et face match.

Les providers sont pluggables (`app/engines/providers/`) : `stub` déterministe pour le
développement, MRZ TD3 réel avec chiffres de contrôle, Tesseract optionnel, sender OTP HTTP.
Brancher un fournisseur commercial revient à implémenter l'interface de `providers/base.py`.

### 3 bis. Orchestrateur réglementaire (`app/engines/orchestrator.py`)

Le routage réglementaire est une **politique explicite**, jamais déduit du document :
un assuré ivoirien peut présenter un passeport congolais — pays du document, pays de
l'assureur et lieu de traitement sont trois choses différentes.

Résolution de la juridiction applicable à la création de session :

1. `jurisdiction` dans `POST /v1/kyc/sessions` (le tenant affirme le contexte) ;
2. `tenant.default_jurisdiction` (marché d'origine du tenant) ;
3. `EKYC_DEFAULT_JURISDICTION` (`GLOBAL` par défaut).

Le profil résolu — `jurisdiction`, `vault_profile`, `retention_days`, `tsa_policy`,
`signature_level` — est **figé sur la session** et hashé dans la chaîne d'audit
(`jurisdiction_source` inclus : `request | tenant_default | platform_default`).

- **Vaults** : `EKYC_VAULTS_JSON` déclare des stockages nommés (root local ou bucket S3,
  potentiellement sur d'autres VPS). `storage.get_vault(name)` résout le backend ;
  chaque artefact de la session y est routé et enregistre son `vault_profile`.
- **TSA** : `tsa_policy` sélectionne le fournisseur — `"internal"` (horodatage logiciel
  marqué non qualifié), `"qualified"` (premier fournisseur qualifié configuré, repli
  honnête sur l'interne sinon) ou le nom d'une TSA déclarée dans `EKYC_TSAS_JSON`.
- **Règles** : registre code dans `orchestrator._RULES`, surcharge/ajout sans code via
  `EKYC_JURISDICTIONS_JSON` — c'est ce qui permet de ne déployer que les coffres et
  profils nécessaires dans chaque marché.

## 4. Chaîne de preuve

Le dossier de preuve embarque : résultats eKYC, empreintes SHA-256, signature RSA
(provider + empreinte de certificat), horodatage (provider + qualifié ou honnêtement
non qualifié), **consentement de l'utilisateur** (`accepted`, `at`, `policy_version` —
la capture est bloquée tant qu'il n'est pas donné ; `CONSENT_GIVEN`/`CONSENT_DECLINED`
sont hashés dans la chaîne), juridiction, et journal d'audit chaîné.

**Vérification par un tiers** : `GET /v1/verify/{sha256}` (public) confirme qu'un
document a été scellé par la plateforme — signature vérifiée en direct avec la clé de
signature, jeton d'horodatage vérifié (signature interne ou structure RFC 3161 +
empreinte). Seules les métadonnées de confiance sont exposées, pas de données tenant
ni d'identité.

### 4 bis. Coffre de données (chiffrement au repos)

`EKYC_STORAGE_ENCRYPTION=true` active le coffre (`app/services/vault.py`) : chaque artefact est
scellé en AES-256-GCM **avant** d'atteindre le backend `local` ou `s3` — le stockage ne voit que
du ciphertext.

- **KEK** (clé maîtresse) hors des données : `EKYC_KEK` (env/KMS) en prod, fichier auto-généré en dev.
- **DEK par tenant** : `HKDF-SHA256(KEK, "ekyc-vault:<tenant>:<version>")` — dérivation
  déterministe, aucune clé en base ; rotation = `EKYC_KEK_VERSION` +1 (les anciens blobs restent lisibles).
- **AAD** : en-tête + `tenant_id` liés au ciphertext — un blob déplacé sous un autre tenant échoue à l'authentification.
- **Format auto-descriptif** (`EKYCENC` magic + version) : les artefacts legacy en clair restent lisibles, migration paresseuse possible.
- **`sha256` = hash du clair** : les preuves d'intégrité et les signatures ne sont pas affectées par le chiffrement au repos.
- **`KeyProvider`** est le point d'extension KMS (AWS KMS, HashiCorp Vault, HSM) via `EKYC_KMS_BACKEND`.

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

## 9. Infrastructure cible et coût par KYC

Le revenu brut est de 300 FCFA par KYC ; l'objectif technique est un coût infrastructure + IA
**inférieur à 30–50 FCFA par vérification**, le reste couvrant SMS OTP, horodatage, stockage,
bande passante et exploitation. Tout l'inférence tourne en local (modèles OCR / face / liveness
open source), aucun appel facturé à l'unité chez un tiers.

```
                MHC · Banque · Fintech · …
                          │
                   Nginx / API Gateway
                          │
                   eKYC API (FastAPI)          ← CPU
                          │
                        Redis
              ┌───────────┴───────────┐
        file `cpu`                 file `gpu`
   hash · PDF · signature      OCR · liveness · face
   OTP · webhooks · audit      embedding / matching
        worker-cpu ×N            worker-gpu ×M   ← pool GPU mutualisé
              └───────────┬───────────┘
                  PostgreSQL · Object storage
```

Décisions :

- **Deux pools de workers** (`app/workers/celery_app.py`) : les tâches vision sont routées sur la
  file `gpu`, tout le reste sur `cpu`. Passer de 1 à 4 GPU = lancer des `worker-gpu`
  supplémentaires ; ni l'API ni MHC ne changent.
- **GPU mutualisé, jamais réservé à un tenant** : la file est unique, les tâches portent le
  `tenant_id` pour la facturation et l'isolation des données, pas pour l'ordonnancement.
- **Exécution CPU↔GPU auto-détectée** (`EKYC_GPU_ENABLED`, `app/engines/providers/runtime.py`) :
  ONNX Runtime utilise `CUDAExecutionProvider` quand le wheel `onnxruntime-gpu` et un device
  NVIDIA sont présents, sinon `CPUExecutionProvider` — le même code et la même file `gpu`
  tournent sur un hôte sans GPU. L'image CUDA dédiée (`Dockerfile.gpu`) ne sert que le pool
  `worker-gpu` via `docker-compose.gpu.yml`.
- **Providers interchangeables** (`app/engines/providers/base.py` : `OcrProvider`,
  `FaceProvider`, `OtpSender`) : remplacer PaddleOCR par Qwen-VL ou un modèle de liveness par un
  autre n'impacte que la configuration (`EKYC_OCR_PROVIDER`, `EKYC_FACE_PROVIDER`).
- **Un seul serveur GPU dédié plutôt que VPS CPU + VPS GPU** tant que le volume ne justifie pas
  la séparation : PostgreSQL, Redis, API, workers CPU et le pool GPU cohabitent ; le stockage
  objet est le premier composant à externaliser quand le volume d'archives croît.
- **Suivi du coût unitaire** : chaque tâche GPU journalise sa durée ; le coût par KYC se déduit
  de `(coût mensuel serveur + SMS) / KYC du mois` et doit être suivi comme un KPI produit.

Ordre de grandeur des seuils : à 50 000–100 000 KYC/mois (15–30 M FCFA), un serveur dédié
16–32 cœurs / 64–128 Go / NVMe / 1 GPU est largement amorti ; au-delà, on ajoute des GPU au pool.

## 10. Suite du produit

La même base porte les briques suivantes : e-signature autonome (signature de documents hors
parcours KYC), vérification externe d'un document par son empreinte, portail tenant et console
d'audit, connecteurs registres d'état civil, rétention/purge automatiques, certification eIDAS avec
une TSA et un HSM qualifiés.
