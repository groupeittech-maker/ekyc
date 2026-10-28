# Services de confiance fournis par le client (BYOC — Bring Your Own Connectors)

Principe : **Trusdy n'embarque pas les services de confiance d'un pays** —
le client/déployeur les fournit et les référence dans son profil pays.
Le moteur ne connaît jamais le prestataire en dur ; il résout des **noms
de connecteurs** vers des implémentations configurées.

## 1. Ce que le client fournit

| Service | Fourni par le client | Configuré dans |
|---|---|---|
| **TSA RFC 3161** (horodatage qualifié) | endpoint + CA de confiance + identifiants | `EKYC_TSAS_JSON` |
| **Signature électronique** | un `Signer` implémenté (DSS/HSM/KMS) ou le signataire plateforme | code + `EKYC_SIGNING_BACKEND` |
| **Profil pays** | noms des connecteurs dans `trust.*` | `country-profiles/<CC>.json` |

## 2. Configuration TSA (par nom)

```bash
EKYC_TSAS_JSON='{
  "digisign": {
    "endpoint": "https://tsa.prestataire-ci.example/rfc3161",
    "auth": {"type": "basic", "username": "…", "password": "…"},
    "trusted_ca_path": "/srv/ekyc/var/keys/tsa/digisign-ca.pem"
  }
}'
```

Puis dans le profil pays :

```json
"trust": {
  "tsa_provider": "digisign",
  "signature_provider": "local",
  "certificate_profile": "ekyc-signing"
}
```

**Chaîne de résolution** : session → juridiction →
`orchestrator.resolve()` → le profil pays activé fournit les connecteurs
par défaut de l'instance (prioritaires sur la règle de juridiction) →
`RegulatoryProfile.tsa_policy="digisign"` snapshoté sur la session +
audit → `tsa.timestamp()` résout le nom vers le prestataire configuré.

**Un nom inexistant échoue ouvertement** (`UnknownTsaProviderError`) —
jamais de dégradation silencieuse vers l'horodatage interne.

## 3. Signature électronique

Deux modes :

- **`signature_provider: "local"`** — le signataire plateforme
  (RSA + cert dans le vault). Convient tant qu'aucune qualification
  externe n'est exigée par le pays.
- **Prestataire externe** — implémenter `app/engines/providers/signers.Signer`
  (`sign`, `verify`, `public_key_pem`, `certificate_fingerprint`,
  `certificate_not_after`) et le dispatcher dans `get_signer()` sur le nom
  déclaré. Les identifiants du prestataire passent par des variables
  `EKYC_SIGNER_<NOM>_*` — jamais dans le profil.

## 4. Vérité sur le niveau de confiance

Le profil **déclare** le connecteur ; il ne peut pas se déclarer
"qualifié" lui-même : la qualification reste un fait du prestataire
(sa chaîne de certificats, sa reconnaissance réglementaire). Trusdy
enregistre dans chaque preuve : provider utilisé, empreinte et
expiration du certificat, politique appliquée — c'est l'auditeur qui
juge la qualification, la plateforme fournit les éléments.

## 5. Checklist de réception d'un connecteur client

- [ ] `EKYC_TSAS_JSON` ou backend `Signer` configuré sur l'instance
- [ ] `country-profiles/<CC>.json` `trust.*` renseigné (noms, pas d'URLs)
- [ ] `bash deploy/national/health-check.sh` → aucun provider dev (`stub`/`log`)
- [ ] Un scellement test (`POST /v1/kyc/sessions/{id}/documents`) montre
      `provider=<nom>` et l'empreinte du certificat attendus
- [ ] La chaîne CA du prestataire est embarquée (`trusted_ca_path`)
