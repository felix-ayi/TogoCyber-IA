# API FastAPI v1

Base URL locale : `http://localhost:8000`. OpenAPI interactif : `/docs`.

## Authentification

`POST /api/v1/auth/register` crée un compte de rôle `User` avec e-mail unique et mot de passe de 12 à 128 caractères. `POST /api/v1/auth/login` renvoie un jeton Bearer valable 30 minutes ; `POST /api/v1/auth/logout` révoque ce jeton et `GET /api/v1/auth/me` renvoie l'identité active. Cinq échecs de connexion depuis une adresse cliente en 15 minutes entraînent une réponse HTTP 429. Aucun mot de passe n'est stocké en clair.

Les analyses, l'assistant et l'historique exigent `Authorization: Bearer <token>`. `User` ne voit que son propre historique ; `Analyst` et `Admin` peuvent consulter l'historique général. Seul `Admin` peut consulter ou provisionner des comptes Analyst/User via `/api/v1/auth/users`. L'inscription publique ne peut jamais attribuer ces rôles. Un premier Admin peut être créé au démarrage avec `BOOTSTRAP_ADMIN_EMAIL` et un mot de passe fort `BOOTSTRAP_ADMIN_PASSWORD` (11 caractères minimum) ; une fois créé, son mot de passe n'est pas remplacé au redémarrage.

## Santé

`GET /api/v1/health` renvoie la santé du serveur, la disponibilité des fichiers modèles (`models.network`, `models.phishing`) et l’état de configuration de l’assistant. `status=healthy` indique la disponibilité du serveur, pas la validité scientifique des modèles.

## Analyse réseau

`POST /api/v1/network/analyze`

```json
{
  "features": {
    "duration": 1.2,
    "src_bytes": 512,
    "dst_bytes": 128,
    "src_packets": 4,
    "dst_packets": 2,
    "src_port": 51515,
    "dst_port": 443,
    "protocol_number": 6,
    "flow_rate": 5
  }
}
```

Toutes les 9 clés sont obligatoires, numériques et finies ; les compteurs, durée, ports et débit ne peuvent pas être négatifs ; ports ≤ 65535 et protocole ≤ 255. Aucune clé supplémentaire n’est acceptée dans le service. Retour : classe bénigne/malveillante, probabilité, confiance, score de risque (0–100), sévérité, indicateurs issus des contributions SHAP, recommandations prudentes et identifiant d’historique (sans valeurs d’entrée stockées). La sévérité découle de la probabilité du modèle et ne confirme pas un incident. HTTP 422 pour données invalides, 503 si modèle non entraîné.

## Analyse phishing

`POST /api/v1/phishing/analyze` avec `{"text":"..."}` (1–20 000 caractères). Retourne classe, probabilité phishing, niveau de confiance, score de risque (0–100), sévérité, indicateurs issus des contributions LIME, recommandations prudentes et identifiant historique. La sévérité ne confirme pas un incident. La prédiction utilise le message complet ; LIME est borné à 200 échantillons et aux 2 000 premiers caractères. `explanation_truncated` signale quand l’explication ne couvre qu’un extrait. Au plus deux analyses phishing simultanées sont admises par processus ; les demandes excédentaires reçoivent HTTP 429. HTTP 422 si vide/invalide, HTTP 503 si modèle absent.

## Inspection URL

`POST /api/v1/url/analyze` avec `{"url":"https://example.org/path"}` (URL HTTP/HTTPS complète, maximum 2 048 caractères). Endpoint authentifié ; vérifie uniquement la structure locale du lien : schéma, nom d’hôte, punycode, identifiants intégrés, raccourcisseurs connus, port, sous-domaines, longueur et quelques termes à risque. Retourne un score heuristique, une sévérité de présentation, les motifs observés et des précautions.

L’URL n’est ni visitée, ni résolue par DNS, ni envoyée à un service tiers ; son contenu n’est pas sauvegardé. Ce score n’est ni une réputation de domaine ni le résultat d’un modèle calibré, et ne confirme pas qu’un site soit malveillant. HTTP 422 pour une URL invalide.

## Assistant

`POST /api/v1/assistant/ask` avec `{"message":"..."}` ; longueur 1–8 000 et contenu non blanc. Nécessite `OPENAI_API_KEY`, sinon 503. Une erreur fournisseur ou réponse invalide n’est pas transformée en succès. Le contenu est envoyé au fournisseur, pas à SQLite.

## Historique

`GET /api/v1/history?limit=50` accepte 1–100 ; métadonnées de résultats, score de risque, sévérité et version de modèle sont retournés selon le rôle du compte.

## Incidents

Un résultat dont le score atteint une sévérité `HIGH` ou `CRITICAL` crée atomiquement un incident `OPEN` associé à l'analyse et au compte. La réponse d'analyse inclut `incident_id` (ou `null` si le seuil n'est pas atteint). Les données stockées restent limitées aux métadonnées de résultat ; ni texte soumis ni caractéristiques de flux ne sont conservés.

`GET /api/v1/incidents?limit=50&status=OPEN` accepte 1–100 résultats et un état optionnel (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`). Un compte `User` ne voit que ses incidents ; `Analyst` et `Admin` voient la file globale. `GET /api/v1/incidents/{id}/events` retourne le journal append-only des changements d'état visible dans le même périmètre.

Seuls `Analyst` et `Admin` peuvent changer l'état via `PATCH /api/v1/incidents/{id}` avec `{"status":"ACKNOWLEDGED"}` ou `{"status":"RESOLVED"}`. Transitions permises : `OPEN` → `ACKNOWLEDGED` → `RESOLVED` ; un incident résolu peut être rouvert en `ACKNOWLEDGED`, et un incident pris en charge peut revenir à `OPEN`. Une transition invalide renvoie HTTP 409. La sévérité n'est qu'un seuil de triage indicatif, pas une preuve de compromission.

## SOC : alertes, incidents et investigation

Sauf mention contraire, les endpoints SOC exigent un jeton `Analyst` ou `Admin`
(HTTP 403 sinon, 401 sans jeton).

- **Alertes** — `GET /api/v1/alerts` (filtres `status`, `severity`, `assignee_user_id`, `limit` 1–100), `GET /api/v1/alerts/counts`, `GET /api/v1/alerts/{id}`, `GET /api/v1/alerts/{id}/events`, `GET /api/v1/alerts/{id}/timeline`. Tri : `PATCH /api/v1/alerts/{id}` (`status` ∈ `NEW`/`INVESTIGATING`/`CONFIRMED`/`FALSE_POSITIVE`/`RESOLVED`/`CLOSED`, note optionnelle) ; transition invalide → HTTP 409. `POST /api/v1/alerts/{id}/assign`, commentaires et tags (`POST`/`DELETE`). Passer une alerte à `FALSE_POSITIVE` ou `CONFIRMED` enregistre un retour modèle (voir supervision ML).
- **Vue d’ensemble** — `GET /api/v1/alerts/overview` : agrégats d’alertes et d’incidents calculés sur les données réelles.
- **Recherche** — `GET /api/v1/search?q=<terme>&limit=20` : recherche globale (alertes, incidents, détections, audit) avec échappement LIKE.
- **Audit** — `GET /api/v1/audit-events?limit=50&action=<action>` : journal immuable, filtrable par action.

## Threat intelligence (IOC)

Base **locale** d’indicateurs gérée par les analystes ; aucun flux externe
(VirusTotal, AbuseIPDB, SIEM…) n’est connecté ni simulé.

- `GET /api/v1/iocs` (filtres `type`, `status`, `severity`, `tag`), `GET /api/v1/iocs/counts`, `GET /api/v1/iocs/{id}`.
- `POST /api/v1/iocs` — valeur validée selon le type (IP, domaine, URL, empreinte 32/40/64/128 hex, e-mail) ; doublon `(type, value)` → HTTP 409 ; valeur invalide → 422. `PATCH /api/v1/iocs/{id}` (`type`/`value` immuables), `DELETE` → 204.
- `GET /api/v1/iocs/lookup?value=…` renvoie les correspondances **actives** locales et `external_sources: []` (honnête : aucune source externe configurée).
- Tags : `POST /api/v1/iocs/{id}/tags`, `DELETE /api/v1/iocs/{id}/tags/{tag}`.

## Corrélation et règles de détection

- **Règles** — `GET/POST /api/v1/correlation/rules`, `GET/PATCH/DELETE /api/v1/correlation/rules/{id}`. Une règle = module (`network`/`phishing`/`any`), `min_severity`, `threshold` (2–100), `window_minutes` (1–1440), `is_active`.
- **Moteur** — `POST /api/v1/correlation/run` évalue chaque règle active sur les alertes réellement présentes dans la fenêtre et crée une corrélation quand le seuil est atteint (idempotent tant qu’une corrélation `OPEN` couvre exactement les mêmes alertes). Retour : `rules_evaluated`, `findings_created`.
- **Corrélations** — `GET /api/v1/correlation/findings` (filtres `status`, `rule_id`), `GET/PATCH /api/v1/correlation/findings/{id}` ; transitions `OPEN`/`ACKNOWLEDGED`/`CLOSED`, invalide → 409. Aucune alerte n’est inventée.

## Supervision ML

Indicateurs calculés **uniquement** sur les détections stockées et les verdicts
analystes. Les caractéristiques brutes n’étant pas conservées, aucun drift
d’entrées (PSI/KS) n’est fabriqué.

- `GET /api/v1/ml/monitoring?days=30` (1–30) : par module, volume, taux de malveillance, répartitions, modèles en usage et « drift » = écart du taux malveillant entre les deux moitiés de la fenêtre ; plus le taux de faux positifs issu des verdicts.
- `GET /api/v1/ml/feedback?limit=50` : derniers verdicts `false_positive`/`confirmed`.

## Playbooks, notifications et intégrations

- **Playbooks** — `GET/POST /api/v1/playbooks`, `GET/PATCH/DELETE /api/v1/playbooks/{id}`. Procédures documentaires ordonnées (module, `min_severity`, étapes). Aucune action automatique sur des systèmes externes.
- **Notifications** — `GET /api/v1/notifications` (+ `counts`). File d’attente alimentée par les vraies alertes `HIGH`/`CRITICAL` ; `delivery_status` = `not_configured` tant qu’aucun canal (SMTP/Slack/webhook) n’est configuré — rien n’est prétendument « envoyé ». `POST /api/v1/notifications/dispatch` tente une diffusion **réelle** via le premier canal configuré (`NOTIFICATION_WEBHOOK_URL`, `NOTIFICATION_SLACK_WEBHOOK` ou `NOTIFICATION_SMTP_HOST/FROM/TO`) et passe chaque message à `sent`/`failed` selon le résultat du transport ; sans canal configuré, la file n’est pas modifiée et aucun envoi n’est simulé.
- **Intégrations** — `GET /api/v1/integrations` : état **réel** de chaque connecteur (Zeek, Suricata, Syslog, VirusTotal, AbuseIPDB, SIEM, canaux de notification) déduit de la présence des variables d’environnement. Une source non configurée est signalée `not_configured` et ne renvoie jamais de télémétrie simulée.

## Exports CSV

- `GET /api/v1/exports/alerts`, `/incidents`, `/iocs` — rôles SOC (`Admin`/`Analyst`) ; `GET /api/v1/exports/audit` — `Admin` uniquement.
- Paramètres : `limit` (1–100, défaut 100) plus les mêmes filtres que les endpoints JSON (`status`, `severity`, `type`, `action`).
- Réponse `text/csv; charset=utf-8` avec `Content-Disposition: attachment`. Les exports réutilisent les requêtes de dépôt déjà soumises aux rôles — aucune donnée supplémentaire n’est exposée.
- Protection contre l’injection de formules tableur : toute cellule texte commençant par `=`, `+`, `-`, `@`, tabulation ou retour chariot est préfixée d’une apostrophe afin de rester inerte à l’ouverture dans Excel/LibreOffice.

## Sécurité d’exploitation

Prototype sans base PostgreSQL, isolation multi-tenant ou limitation de débit globale : ne pas exposer publiquement sans reverse proxy TLS, authentification, limitation partagée de fréquence, supervision et contrôles opérateur. La limite de concurrence phishing est locale à chaque processus. CORS configurable ; ne permet aucun scan réseau.