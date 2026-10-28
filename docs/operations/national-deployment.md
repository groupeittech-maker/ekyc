# Déploiement d'une instance nationale Trusdy

Procédure cible : un opérateur autorisé installe une instance complète
sans intervention du centre, puis la fait activer par attestation signée.

## Pré-requis hôte

- Ubuntu 22.04+/24.04, 2 vCPU / 8 Go RAM minimum (KVM 2 validé)
- Docker 24+ et plugin compose
- Un nom de domaine pointant vers l'hôte (ex. `ekyc.example.tld`)
- nginx + certbot sur l'hôte (vhost → `127.0.0.1:8300`)

## Séquence

```bash
# 1. Récupérer le package versionné
tar -xzf trusdy-national-<ver>.tar.gz -C /var/www/ekyc && cd /var/www/ekyc

# 2. Installer (idempotent — relançable)
bash deploy/national/install.sh --domain ekyc.example.tld \
    --profile country-profiles/CI.json

# 3. nginx + TLS
cp deploy/vps/nginx-ekyc.conf /etc/nginx/sites-available/ekyc.conf
# adapter server_name → certbot --nginx -d ekyc.example.tld

# 4. Enrôlement auprès du centre
bash deploy/national/enroll.sh \
    --central https://central.srv1992558.hstgr.cloud \
    --bootstrap <clé-amorçage> --country CI

# 5. Attestation (côté Central, après validations métier)
curl -X POST $CENTRAL/v1/instances/<id>/attestations \
    -H "X-Admin-Key: …" -d '{"legal_review":true,"hosting_approved":true,
                             "trust_services_validated":true}'
# → insérer le document retourné dans country-profiles/CI.json
#   (champ activation_attestation) puis recréer les conteneurs.

# 6. Vérifier à tout moment
bash deploy/national/health-check.sh ekyc.example.tld
```

## Ce que l'installateur garantit

- Secrets générés une seule fois (`.env` préservé aux relances)
- Postgres/Redis privés, API loopback uniquement
- Modèles biométriques téléchargés avant que l'API ne serve en prod
- Clé de signature + certificat générés dans le volume `archive`
- Profil pays installé + `EKYC_REQUIRE_COUNTRY_PROFILE=true` — l'instance
  refuse de démarrer sans attestation valide du centre
- Magasin CSCA (masterlist BSI) rafraîchissable via `scripts/fetch_csca`

## Autonomie & perte du centre

- La nationale fonctionne sans Central tant que son attestation est valide.
- Heartbeats en échec → warning uniquement ; sessions et décisions continuent.
- Une attestation expirée empêche le redémarrage en production — à renouveler
  via le centre avant `not_after`.

## Multi-pays

Un pays = un fichier `country-profiles/<CC>.json` + un enrôlement + une
attestation. Aucune branche de code par pays. Le manifeste signé du centre
distribue ensuite les réglages whitelists (seuils) à chaud.
