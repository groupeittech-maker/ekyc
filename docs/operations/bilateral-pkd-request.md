# Dossier technique standard — demande d'accès PKD national

Modèle à envoyer aux autorités nationales (ANTS, ONI, services
d'immigration) pour compléter la couverture CSCA/CRL par échange
bilatéral. Le canal OACI PKD reste prioritaire ; ce dossier couvre les
pays absents des Master Lists publiques.

## À envoyer (demande)

1. **Certificats CSCA officiels** du pays, en DER ou PEM, accompagnés
   de leurs empreintes SHA-256 sur un canal authentifié distinct.
2. **Master Lists nationales** le cas échéant, avec leur format
   (.ml CMS signé, zip, LDIF).
3. **CRL en cours** + mode d'actualisation (URL stable, fréquence,
   signature par quelle autorité).
4. **Procédure de vérification** : qui signe la Master List nationale,
   sous quelle chaîne — pour que la provenance soit vérifiable et non
   seulement téléchargée.
5. **Dispositif d'essai** : accès à des passeports de test ou à un
   programme de test autorisé — le niveau L3 (passeport réel vérifié)
   ne peut être atteint autrement.

## À joindre (à propos de Trusdy)

- Description : plateforme eKYC souveraine, auto-hébergée par pays,
  données et clés résidentes, aucun transfert vers un cloud tiers.
- Usage : vérification d'identité pour clients assurés (MHC Côte
  d'Ivoire, déploiement CI en production).
- Politique de données : biométrie chiffrée AES-256, rétention bornée,
  aucune collecte biométrique par le centre.
- Preuves : audit hashé, signatures RSA, authentification passive
  ICAO Doc 9303 (EF.COM, SOD, DSC→CSCA).

## Ce que nous nous engageons à faire

- N'ajouter un CSCA au trust store qu'après vérification de sa
  provenance, de sa signature et de sa chaîne — jamais un certificat
  trouvé "en ligne" sans ancrage.
- Traiter les CRL avec signature vérifiée, fraîcheur contrôlée et
  politique explicite : l'absence de CRL n'est pas une révocation.
- Respecter les modalités d'actualisation indiquées par l'autorité.
- Ne jamais présenter un passeport comme "vérifié" sans chaîne
  complète — l'indéterminé reste en revue humaine.

## Suivi interne par pays

Maintenir pour chaque pays cible (NG, SN, ML, BF, GN, GA, CG, CD en
priorité) un état à 5 niveaux :

| Niveau | Signification | Source |
|---|---|---|
| 1 | CSCA disponible (sourcé, vérifié) | `csca_coverage` |
| 2 | CSCA valide à date | `csca_coverage` |
| 3 | Chaîne DSC vérifiable | tests NFC réels |
| 4 | Révocation contrôlée | CRL présente + fraîche |
| 5 | Passeport testé | procédure d'essai documentée |
