# Revue de sécurité interne — pré-pentest (LOT B phase 1)

Revue de code + tests dédiés effectuée sur la surface autorisée. Ce
document n'est **pas** un pentest indépendant — il prépare le terrain et
corrige ce qui est trouvable sans audit externe.

## Vulnérabilités trouvées et corrigées

| ID | Sévérité | Constat | Correction |
|---|---|---|---|
| **B1** | **Haute** | `POST /v1/oauth/token` sans rate-limit → brute-force de `client_secret` possible en boucle | Throttle : 10 req/10min par `client_id`, 50/10min par IP source → 429. Tests `test_oauth_bruteforce` (spray + rotation cid) |
| **B2** | **Moyenne** | `/docs` Swagger exposé en production → énumération complète de l'API | `docs_url=None` en prod (`_docs_enabled()`), `/` redirige vers `/health` |

## Surfaces vérifiées — conformes

| Contrôle | État |
|---|---|
| **IDOR cross-tenant** | `get_tenant_session` → 404 si `tenant_id` diffère (n'apprend pas l'existence) |
| **Clé admin** | `hmac.compare_digest` — timing constant ; router-level `Depends` |
| **Upload** | sniffing magic-bytes (JPEG/PNG/WEBP), taille bornée, MIME déclaré ignoré |
| **Session bearer** | hash vérifié, token à usage unique pour le transfert QR, scopé session |
| **OTP** | caps session+destination, cooldown, invalidation au re-send, jamais logué |
| **Webhooks** | HMAC + rejeu rejeté, timestamp vérifié |
| **Attestation/manifeste** | signature Ed25519 + pays + flags + expiration — forge rejetée |
| **Heartbeat** | `jti` persistant en base → rejeu impossible |
| **Erreurs** | réponses `{"detail": ...}` — pas de stack, chemins ou secrets (test dédié) |

## Risques résiduels documentés

| ID | Gravité | Risque | Traitement |
|---|---|---|---|
| R1 | Basse | `X-Forwarded-For` spoofable → contourne le cap IP si l'app n'est pas strictement derrière nginx | cap `client_id` reste le garde effectif ; valider la config proxy en prod |
| R2 | Basse | `ratelimit` dégradé par-processus si Redis down (30 s) | contournable multi-instance ; acceptable — mieux que pas de limite |
| R3 | Moyenne | brute-force du `session_token` (bearer 32 octets aléatoires) | entropie rend la pratique infaisable ; monitorer le volume |
| R4 | Moyenne | OCR dégradé (Tesseract absent → stub impossible en prod) | fail-closed au boot — vérifié |
| R5 | Basse | `/docs` dans l'image — masqué en prod mais présent | supprimer de l'image de prod si durcissement voulu |

## Couverture ajoutée

- `test_oauth_bruteforce` (4) : cap client_id, cap IP, docs off prod, erreurs sans fuite
- 189 tests au total — non-régression complète
