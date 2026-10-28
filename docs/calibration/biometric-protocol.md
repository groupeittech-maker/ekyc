# Protocole de calibration biométrique — FAR/FRR avant seuils de production

Objectif : justifier les seuils en production par des mesures reproductibles
sur des données représentatives — pas les modifier "à l'œil".

## Deux métriques à ne pas confondre

| Moteur | Métrique | Enjeu |
|---|---|---|
| **SFace** (comparaison portrait↔selfie) | FAR/FRR/EER sur paires | FAR = usurpation acceptée (sécurité) ; FRR = légitime rejeté (UX) |
| **MiniFAS** (anti-spoof / PAD) | spoof FAR, live FRR (métriques PAD, pas FAR/FRR de match) | spoof FAR = attaque de présentation acceptée — **doit tendre vers 0** |

## Datasets attendus

```
var/benchmark_faces/          # SFace — par cohorte (condition de capture)
├── low_end_android/          #   cohortes : modèle d'appareil
│   └── <person_id>/*.jpg
├── mid_range/
├── bright_light/             #   cohortes : éclairage
└── low_light/

var/benchmark_liveness/       # MiniFAS — PAD
├── live/                     # captures réelles
└── spoof/                    # écrans, impressions, replays, masques
```

Constitution : échantillons consentis, représentatifs des utilisateurs
cibles (appareils réels du marché, éclairages réels) ; aucune donnée de
production. LFW peut servir de smoke test pipeline — **jamais** de
justification de seuil africain.

## Méthode

```bash
# 1. Cohortes séparées — le pire cohorte gouverne le seuil
python -m scripts.benchmark_sface --dataset-dir var/benchmark_faces \
    --cohorts --threshold 0.5 --output reports/sface-<date>.json

# 2. PAD séparément — métriques PAD ≠ métriques de match
python -m scripts.benchmark_antispoof --dataset-dir var/benchmark_liveness \
    --threshold 0.6 --output reports/antispoof-<date>.json

# 3. Critères de sortie — échec → seuil non shippable
python -m scripts.benchmark_sface --dataset-dir var/benchmark_faces --cohorts \
    --far-target 0.001 --frr-target 0.05
```

## Critères d'acceptation (à figer après première mesure)

| Métrique | Cible initiale | Justification |
|---|---|---|
| SFace FAR par cohorte | ≤ 0.1 % | taux d'usurpation acceptable pour eKYC |
| SFace FRR par cohorte | ≤ 5 % | l'excès coûte en recapture et en ressenti |
| MiniFAS spoof FAR | = 0 mesuré | toute attaque acceptée est une faille |
| MiniFAS live FRR | ≤ 10 % | UX tolérable, re-vérifier sur field data |

Le seuil retenu est le **maximum** qui satisfait toutes les cohortes —
une moyenne globale masque les cohortes défaillantes.

## Gouvernance des seuils

- Les seuils de prod sont `EKYC_*_THRESHOLD` — **modifiables uniquement par
  manifeste signé** (whitelist `runtime_config`) ou par env + revalidation.
- Chaque changement = nouveau rapport benchmark archivé (`reports/`) +
  version du modèle + dataset hash.
- Une dégradation de cohorte post-MAJ = rollback par manifeste.

## Conditions de sortie

- [ ] FAR/FRR/EER mesurés par cohorte sur dataset indépendant de l'entraînement
- [ ] spoof FAR ≈ 0 documenté sur attaques représentatives
- [ ] Seuils écrits avec justification + rapport archivé
- [ ] Limites connues documentées (cohortes sous-représentées)
