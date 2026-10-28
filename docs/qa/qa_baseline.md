# QA Baseline — état de référence des tests Trusdy

**Date** : 2026-10-28 · **Suite** : 185 tests — **100 % PASS** en ~35 s
**Couverture** : **84 %** (4344 statements, mesuré `pytest --cov`)

> Mise à jour : +10 tests comblant les écarts haute priorité —
> `test_heartbeat_manifest` (7) et `test_timestamp` (3). Le test e2e
> "Central injoignable" est couvert par `central_down_is_autonomy` +
> `manifest_unreachable` — autonomie prouvée en suite, pas seulement
> en production.

Cette baseline cartographie la suite existante par parcours métier avant
d'ajouter quoi que ce soit — per mission LOT A.

## 1. Couverture par parcours métier

| Parcours | Fichiers de test | État |
|---|---|---|
| Création/isolation tenants | `test_kyc_flow` (minimisé, scoped, flow refused), `test_orchestrator` (juridiction, vault routing, admin storage) | ✅ solide |
| Consentement | `test_consent_verify` (7) — version refusée, consentement décliné, capture bloquée | ✅ |
| Dépôt document + recapture | `test_recapture_nfc` (RETRY borné, recto/verso, unreadable→review) | ✅ |
| OCR/MRZ | `test_kyc_flow` (parsing + audit), `test_recapture_nfc` (TD, check digits, tampered doc number, VIZ crosscheck), `test_units` (digits) | ✅ branches avancées partielles (identity.py 86 %) |
| Capture faciale + PAD | `test_inhouse` (liveness, bounded), `test_kyc_flow` (budget rejet) | ⚠️ provider antispoof 30 % — modèle non chargé en test |
| Face-match | `test_kyc_flow` (failure→review), `test_inhouse` (cosine norm) | ⚠️ pipeline unitaire seulement |
| NFC passeport | `test_recapture_nfc` (VALID, tampered, CSCA inconnu→INDETERMINATE), `test_revocation` (CRL 6 cas) | ✅ passport_pki 81 % |
| Décision | `test_units` (engine), `test_resilience` (décision terminale non écrasée, idempotence, override audité) | ✅ |
| OTP | `test_otp_security` (10) — cooldown, caps, invalidation, expiration, jamais logué | ✅ excellent |
| Webhooks | `test_mhc_client` (signature, tamper, replay), `test_resilience` (delivery) | ✅ |
| Audit/preuves | `test_evidence` (3), `test_signing` (2), `test_consent_verify` (verify endpoint + metadata) | ✅ |
| Rétention/suppression | `test_retention` (3) — purge PII, idempotent, session ouverte | ✅ |
| Autonomie sans Central | `test_manifest` (disabled/unreachable), `test_heartbeat_manifest` (autonomie prouvée), `test_control_plane` | ✅ |
| Config prod | `test_prod_config` (10) — secrets refusés, providers dev, cert auto-signé | ✅ |
| Central↔National | `test_control_plane` (7), `test_country_profile` (12), `test_manifest` (5), `test_trust_wiring` (4) | ✅ durci après audit |

## 2. Couverture par module — lacunes quantifiées

| Module | Cover | Lacune |
|---|---|---|
| `providers/tesseract.py` | **0 %** | provider externe — jamais exercé (mockable) |
| `engines/timestamp.py` | **0 %** | utilitaire RFC 3161 non testé |
| `services/heartbeat.py` | **27 %** | modes d'échec, payload counters, jamais testé |
| `providers/antispoof.py` | **30 %** | modèle ONNX absent en test — branches model-load |
| `providers/runtime.py` | **38 %** | initialisation providers au boot |
| `providers/inhouse.py` | **41 %** | chemins réels ONNX — besoin des modèles ou mocks |
| `services/manifest.py` | **46 %** | chemins HTTP (`not-yet-effective`, `already-applied`, `unreachable`) |
| `engines/ratelimit.py` | **73 %** | branches Redis réelles vs fallback |
| `engines/passport_pki.py` | **81 %** | chemins ECDSA, DG non fournis, exceptions rares |

## 3. Anomalies et écarts classés par gravité

| Gravité | Écart | Justification |
|---|---|---|
| ~~Haute~~ | ~~Pas de test "Central injoignable"~~ | ✅ `test_heartbeat_manifest::test_central_down_is_autonomy` + `test_manifest_unreachable` — autonomie prouvée en suite |
| ~~Haute~~ | ~~`heartbeat.py` 27 %~~ | ✅ JWT structure, payload agrégé, échecs — 7 tests |
| ~~Moyenne~~ | ~~`manifest.py` chemins réseau~~ | ✅ `not-yet-effective`, `unreachable`, `none-published` couverts |
| **Moyenne** | `antispoof.py` 30 % — pas de test du chargement modèle + fail-closed | le point le plus sensible de la sécurité en prod |
| **Moyenne** | `tesseract.py` 0 % | provider alternatif jamais validé |
| ~~Moyenne~~ | ~~`timestamp.py` 0 %~~ | ✅ wrapper + politique honnête testés |
| **Moyenne** | Aucun test OCR sur dégradations (flou, rotation, faible résolution, reflets) | attendu par LOT C — mesure, pas juste présence |
| **Basse** | Pas de test "deux dossiers même numéro document scopé tenant" sous charge concurrentielle | couvert à un client, pas sous contention |
| **Basse** | `inhouse.py` 41 % — branches ONNX réelles | liée au P0 calibration, pas aux tests unitaires |
| **Basse** | `ratelimit.py` 73 % — pas de test Redis down → dégradé | comportement réel inconnu |

## 4. Suite de non-régression

La suite actuelle **est** la suite de non-régression : 185 tests, ~35 s,
déterministe (fake Redis/SQLite, modèles stubbed, fetchers jamais réseau).
Toute nouvelle correction s'ajoute ici. Commande : `python -m pytest -q`.

## 5. Ordre d'exécution proposé (LOT B→F)

| Ordre | Lot | Première action concrète |
|---|---|---|
| 1 | **A résiduel** | combler heartbeat/manifest/antispoof/tesseract/timestamp (écart haute) + e2e autonomie Central-down |
| 2 | **C — OCR/MRZ** | dataset synthétique dégradations + rapport mesures (`ocr_mrz_calibration_report.md`) |
| 3 | **D — Biométrie** | cohortes + gates acceptation → `biometric_calibration_report.md` |
| 4 | **E — Passeports africains** | inventaire format par pays + `african_document_test_coverage.md` |
| 5 | **B — Pentest** | scope staging → rapport → corrections → contre-test |
| 6 | **F — Validation finale** | corrections, seuils justifiés, non-régression, risques résiduels |

Pentest en 5ᵉ parce que les lots A/C/D/E peuvent révéler des bugs
qu'il vaut mieux corriger **avant** l'audit externe — le pentest doit
toucher le système stable, pas ses régressions en cours.
