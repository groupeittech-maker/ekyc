# Collecte pilote MHC — dataset de calibration et connaissance documentaire

Mécanisme : la phase de test MHC en conditions réelles alimente à la fois
le dataset de calibration (biométrie + documents) et les statistiques de
couverture documentaire — **deux flux distincts et gouvernés**.

## 1. Deux flux, deux règles différentes

| Flux | Contenu | Condition | Destination |
|---|---|---|---|
| **Observations** (automatique) | format MRZ, pays, type, statut, signaux | toutes les analyses | `document_observations` — **aucune PII**, jamais de n° document, nom, MRZ |
| **Don d'échantillons** (opt-in) | images document + selfies | `donate_samples=true` **au consentement** par le testeur | `var/dataset_donation/<format>/` |

Règle absolue : le don n'est jamais implicite — `ConsentRequest.donate_samples`
est `false` par défaut et le testeur le coche explicitement.

## 2. Ce que le testeur voit

L'écran de consentement pilote affiche deux lignes :

- ☑ « J'accepte le traitement de ma vérification d'identité » — obligatoire
- ☐ « J'accepte que mes documents et selfies servent à améliorer le moteur
  (dataset de calibration anonymisé) » — **optionnel**, `donate_samples`

Sans la seconde case : la vérification fonctionne normalement, seule
l'observation non-personnelle est enregistrée.

## 3. Organisation du dataset collecté

```
var/dataset_donation/
├── TD3/
│   ├── <uuid>-0.jpg          # document recto
│   ├── <uuid>-1.jpg          # verso (cartes)
│   └── <uuid>.json           # sidecar labels : format, pays, type — PAS de session
├── TD1/  ├── unknown/
```

Pour la biométrie, les selfies donnés suivent la même convention ; les
cohortes (appareil, éclairage) sont étiquetées **par le testeur** au
moment du don via le questionnaire pilote (modèle de téléphone,
conditions) — jamais déduites automatiquement.

## 4. Consommation par les outils existants

- `benchmark_sface --cohorts` → déplacer les selfies donnés dans
  `var/benchmark_faces/<cohorte>/<personne>/`
- `benchmark_antispoof` → `live/` et `spoof/`
- `GET /v1/admin/document-stats` → tableau de bord couverture :
  formats inconnus détectés, pays vus, taux d'échec par format

## 5. Garde-fous

- L'image du passeport reste un document d'identité réel → accès au
  répertoire `dataset_donation` restreint (ops calibrateur uniquement),
  rétention bornée, jamais commitée.
- Le sidecar n'enregistre ni session, ni tenant, ni nom — anonymat
  technique, le document lui-même étant le contenu donné.
- Une MRZ complète ou un n° de document n'apparaît **jamais** dans
  `document_observations` — vérifié par `test_document_stats`.
- Le don peut être refusé sans conséquence sur la vérification.

## 6. Questionnaire testeur (cohortes)

À remplir par chaque volontaire lors du don :

- modèle de téléphone : ________
- éclairage : ☐ intérieur  ☐ extérieur  ☐ faible lumière
- document : ☐ passeport  ☐ carte nationale  ☐ pays : __
- simulacre d'attaque (pour liveness) : ☐ photo sur écran  ☐ impression  ☐ vidéo

Ces métadonnées alimentent les cohortes — le dataset final est
constitué à froid, hors prod, avec validation de chaque échantillon.
