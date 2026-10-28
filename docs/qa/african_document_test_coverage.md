# Couverture documentaire africaine — inventaire par pays et niveau de validation

**Niveaux de vérité** — un format n'est jamais "validé" par un synthétique :

| Niveau | Signification |
|---|---|
| L1 spec-known | format documenté ICAO 9303 / publié — compréhension structurelle |
| L2 synthetic-tested | cas de test générés (MRZ fictives) passent le pipeline |
| L3 specimen-tested | spécimen autorisé réel mesuré — seul niveau "production" |
| L4 pkd-chained | CSCA du pays dans le trust store → authentification passive possible |

## 1. Pays prioritaires (marché MHC)

| Pays | Passeport | CSCA store | ID nationale | Diplo/service | Niveau atteint |
|---|---|---|---|---|---|
| **CI Côte d'Ivoire** | TD3 | **5 certs** | TD1 (`IDCIV`) | TD3 (`PD`/`PS`) | L1+L2+L4 — spécimen à mesurer |
| **CM Cameroun** | TD3 | **6 certs** | TD1 | TD3 | L1+L2+L4 |
| **TG Togo** | TD3 | 1 cert | TD1 | TD3 | L1+L2+L4 |
| **BJ Bénin** | TD3 | 3 certs | TD1 | TD3 | L1+L2+L4 |
| **MA Maroc** | TD3 | 4 certs | TD1 (`CNI`) | TD3 | L1+L2+L4 |
| **DZ Algérie** | TD3 | 3 certs | TD1 | TD3 | L1+L2+L4 |
| **RW Rwanda** | TD3 | 3 certs | TD1 | TD3 | L1+L2+L4 |
| **KE Kenya** | TD3 | 4 certs | TD1 | TD3 | L1+L2+L4 |
| **UG Ouganda** | TD3 | 5 certs | TD1 | TD3 | L1+L2+L4 |
| **TZ Tanzanie** | TD3 | 5 certs | TD1 | TD3 | L1+L2+L4 |
| **AO Angola** | TD3 | 1 cert | TD1 | TD3 | L1+L2+L4 |
| **BW Botswana** | TD3 | 4 certs | TD1 | TD3 | L1+L2+L4 |
| **NA Namibie** | TD3 | 5 certs | TD1 | TD3 | L1+L2+L4 |
| **ZW Zimbabwe** | TD3 | 3 certs | TD1 | TD3 | L1+L2+L4 |
| **MZ Mozambique** | TD3 | 1 cert | TD1 | TD3 | L1+L2+L4 |

## 2. Lacunes explicites — pays non couverts par le trust store

| Pays | CSCA | Source potentielle | Niveau actuel |
|---|---|---|---|
| **NG Nigeria** | ❌ | `immigration.gov.ng/pki-pkd/` — page publiée, fichiers 404 à date | L1+L2 — **passeport lisible, chaîne non vérifiable** |
| **SN Sénégal** | ❌ | ANTS Dakar — échange bilatéral (dossier prêt) | L1+L2 |
| **ML Mali** | ❌ | bilatéral | L1+L2 |
| **BF Burkina Faso** | ❌ | bilatéral | L1+L2 |
| **GN Guinée** | ❌ | bilatéral | L1+L2 |
| **GA Gabon** | ❌ | bilatéral | L1+L2 |
| **CG Congo** | ❌ | bilatéral | L1+L2 |
| **CD RDC** | ❌ | bilatéral | L1+L2 |

> Effet en production : un passeport de ces pays passe OCR/MRZ +
> biométrie, mais la vérification NFC donne `INDETERMINATE` → **REVIEW
> humaine** — jamais un faux rejet, jamais un faux "vérifié".

## 3. Familles de documents et formats

| Famille | Format MRZ | Couverture parser | Spécimens |
|---|---|---|---|
| Passeport ordinaire | TD3 (2×44) | ✅ testé synthétique q0-q2 | à collecter |
| Passeport diplomatique | TD3 (`P<D`) | ✅ même structure, type prefixe diffère | à collecter |
| Passeport de service | TD3 (`P<S`) | ✅ | à collecter |
| Carte ID nationale | TD1 (3×30) | ✅ testé (IDCIV-like) | à collecter |
| Carte ID TD2 | TD2 (2×36) | ✅ testé (finding F-C1 : checks composite plus faibles) | à collecter |
| Visa | TD2 | ✅ format partagé | — |
| Permis/conduite | hors ICAO | ❌ non couvert — non document de voyage | — |

## 4. Méthode d'enrichissement (§6.3 de la mission)

- Métadonnées non personnelles à enregistrer par analyse : `mrz_format`,
  `issuing_country`, `document_type`, statuts de checks — **jamais** la
  MRZ complète, le portrait, ni les champs d'identité.
- Signal `unknown_format` → proposition d'amélioration → tests →
  validation avant activation (pas d'apprentissage à chaud).
- Statistiques par pays conservées dans l'audit agrégé, pas par session.

## 5. État honnête

- **Structurellement prêt** : tout document ICAO 9303 (TD1/TD2/TD3) est
  parsé et ses chiffres de contrôle vérifiés — indépendamment du pays.
- **Couverture de confiance** : 15 pays africains chaînent cryptographiquement ;
  8 prioritaires manquants → REVIEW, sourcing bilatéral/PKD en cours.
- **Validation réelle (L3)** : zéro spécimen mesuré à date — la couverture
  est L1+L2+L4, pas production-mesurée. Premier spécimen à cibler : CI.
