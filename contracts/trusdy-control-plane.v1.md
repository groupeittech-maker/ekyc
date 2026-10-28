# Trusdy — contrat d'interface Central ↔ National (v1)

Statut : **normatif pour les nouvelles intégrations**. L'instance nationale
DOIT fonctionner sans le centre une fois activée ; le centre NE DOIT JAMAIS
recevoir ni demander de clé privée, d'artefact biométrique ou de contenu
utilisateur.

## 1. Rôles

| | Trusdy Central | Trusdy National |
|---|---|---|
| Rôle | Pilotage : registre, versions, licences, attestation, supervision | Traitement : sessions eKYC complètes |
| Détient | clé privée de signature des attestations et manifestes | ses propres clés (signer, KEK, JWT, webhooks) |
| Ne reçoit jamais | — | données biométriques, artefacts, clés privées, contenus OTP |

## 2. Identité des instances

- Chaque instance nationale génère une paire Ed25519 locale ; seule la clé
  publique remonte au centre (`instance_public_key`).
- `instance_id` : UUID alloué par le centre à l'enrôlement.
- Toute requête nationale → centre porte un JWT signé par `instance_public_key`
  (`typ: instance`, `sub: instance_id`, `exp` ≤ 5 min) en `Authorization: Bearer`.

## 3. Flux

### 3.1 Enrôlement — `POST /v1/instances`
National (clé d'amorçage opérateur `X-Bootstrap-Key`, usage unique) → Central.

```json
{
  "instance_public_key": "<pem|b64 Ed25519>",
  "country_code": "CI",
  "deployment_mode": "national",
  "software_version": "0.1.0",
  "capabilities": ["ocr","mrz","nfc","face_match","liveness"]
}
```
Réponse `201` : `{ "instance_id", "central_public_key" }` — la clé publique du
centre est alors scellée dans `.env` (`EKYC_CENTRAL_PUBLIC_KEY`).

### 3.2 Attestation d'activation — `POST /v1/instances/{id}/attestations`
Central signe (Ed25519) le payload canonique
`country|legal|hosting|trust|issued_at|not_after` quand les trois validations
métier sont faites hors-ligne. Le document retourné s'insère dans le profil
pays (`activation_attestation`). En production,
`enforce_country_profile()` refuse le démarrage sans attestation valide et
non expirée — **fail-closed**.

### 3.3 Heartbeat — `POST /v1/instances/{id}/heartbeat`
Toutes les 5 min (autonomie : sans centre, la nationale continue).

```json
{ "version": "0.1.0",
  "counters": {"sessions": {"CREATED": 12, "VERIFIED": 9, "REVIEW": 1},
               "checks": {"DOCUMENT_VERIFICATION:RETRY": 3}},
  "health": {"db": true, "redis": true, "models": true},
  "profile": {"country_code": "CI", "activated": true} }
```
Compteurs et états **uniquement** — jamais d'identifiants, de scores,
d'artefacts ni de destination OTP.

### 3.4 Manifeste signé — `GET /v1/instances/{id}/manifest`
Distribution des config overlay et mises à jour.

```json
{ "version": "0.2.0", "not_before": "…",
  "config_overlay": {"EKYC_RISK_ACCEPT_THRESHOLD": "82"},
  "artifacts": [{"name": "app", "sha256": "…", "url": "…"}],
  "signature": "<b64 Ed25519 sur le payload canonique>" }
```
Une nationale applique un manifeste si : signature valide, `not_before`
atteint, version ≥ courante — sinon elle conserve l'état courant.

### 3.5 Révocation d'attestation — `DELETE /v1/instances/{id}/attestations`
Le centre révoque (compliance) : la nationale appliquera le retrait au
prochain `manifest` ou au `not_after` le plus proche — pas d'arrêt brutal en
cours de traitement d'un dossier.

## 4. Règles de sécurité

- `POST /v1/instances` : `X-Bootstrap-Key` opérateur, à usage unique.
- Toutes les autres requêtes : JWT d'instance (Ed25519, ≤ 5 min).
- Les secrets nationaux (`EKYC_KEK`, `JWT_SECRET`, clés de signature)
  ne quittent **jamais** l'instance.
- Le centre n'a aucun accès aux données des tenants ni aux décisions
  individuelles — seuls compteurs agrégés et état technique.
- Rejeu : `jti` + fenêtre ±60 s côté centre.

## 5. Règle d'autonomie

Centre indisponible → la nationale continue sur son dernier profil attesté
(attestation non expirée) : sessions, OTP, décisions, webhooks. Elle ne peut
PAS s'auto-attester ni activer de nouvelles fonctions de confiance.
