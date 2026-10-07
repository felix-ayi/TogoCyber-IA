# Base de données

## Moteur et emplacement

Le prototype utilise **SQLite** via le module standard `sqlite3` (aucun serveur à
installer). Le fichier local est `database/togocyber.sqlite3`, créé au démarrage
de l’API. Il est **ignoré par Git** (`database/*.sqlite3`) : chaque installation
part de zéro ou conserve ses propres données.

Le chemin est configurable avec `TOGOCYBER_DB_PATH` (voir `.env.example`). En
Docker Compose, la base est montée sur le volume persistant `togocyber-data`
(`/app/database`), donc les utilisateurs, sessions et historiques survivent aux
redémarrages de conteneur.

## Source du schéma

Le schéma fait autorité à deux endroits **à garder synchrones** :

- `database/schema.sql` — référence lisible et documentée ;
- `backend/app/models/database_models.py` — constante `SCHEMA_SQL` réellement
  appliquée au démarrage (auto-contenue, sans dépendance de chemin de fichier).

Toute évolution du schéma doit modifier les deux. `initialize_database()`
(voir `backend/app/repositories/history_repository.py`) exécute `SCHEMA_SQL`
puis applique des migrations additives, et lance la purge de rétention.

## Initialisation et migrations

L’initialisation est **idempotente et non destructive** :

- toutes les tables/index utilisent `CREATE ... IF NOT EXISTS` ;
- les colonnes ajoutées après coup (`user_id`, `risk_score`, `severity`,
  `model_name`, `model_version` sur `analysis_history`) sont créées par
  `ALTER TABLE ... ADD COLUMN` seulement si elles sont absentes ;
- aucune donnée existante n’est supprimée par une migration.

Il n’y a pas encore d’outil de migration versionné (de type Alembic) : les
évolutions restent additives. Pour une base de production PostgreSQL, introduire
un gestionnaire de migrations avant tout changement de schéma destructif.

## Tables

| Table | Rôle | Points clés |
| --- | --- | --- |
| `users` | Comptes et rôles | `email` unique (insensible à la casse), `password_hash` PBKDF2, `role` ∈ `Admin`/`Analyst`/`User`, `is_active`. |
| `auth_sessions` | Jetons révocables | `token_id_hash` (SHA-256 du `jti`), `expires_at`, `revoked_at` ; `ON DELETE CASCADE` depuis `users`. |
| `auth_login_attempts` | Anti brute-force | `client_hash` + `attempted_at`, fenêtre glissante de 15 min, 5 échecs max. |
| `analysis_history` | Historique des analyses | `module` ∈ `network`/`phishing`, prédiction, confiance, `risk_score`, `severity`, `model_name/version`, `user_id`. |
| `events` | Événements normalisés ingérés | EVE Suricata soumis par API, hash SHA-256 déterministe comme clé, champs communs et `raw_event` JSON borné à 64 KiB, purge par `ingested_at` après `RETENTION_DAYS`. |
| `incidents` | Incidents SOC | Créés automatiquement pour `severity` ∈ `HIGH`/`CRITICAL` rattachée à un utilisateur ; `status` ∈ `OPEN`/`ACKNOWLEDGED`/`RESOLVED`. |
| `incident_status_events` | Journal des changements d’état | Historise chaque transition de statut d’un incident. |
| `alerts` | File de triage SOC | Créées pour `severity` ∈ `MEDIUM`/`HIGH`/`CRITICAL` ; liées à la détection source et, le cas échéant, à l’incident. |
| `alert_status_events` | Journal de triage | Chaque transition de statut d’alerte, avec acteur et note. |
| `alert_comments` / `alert_tags` | Collaboration analystes | Commentaires et étiquettes normalisées (minuscules) par alerte. |
| `iocs` / `ioc_tags` | Threat intelligence locale | Indicateurs (ip/domain/url/hash/email) gérés par les analystes ; `UNIQUE(type, value)`, `status` ∈ `ACTIVE`/`EXPIRED`/`REVOKED`. Aucun flux externe. |
| `detection_rules` | Règles de corrélation | Seuils analystes : module, `min_severity`, `threshold` (2-100), `window_minutes` (1-1440), `is_active`. |
| `correlation_findings` / `correlation_finding_alerts` | Corrélations | Créées par le moteur quand de vraies alertes atteignent un seuil ; liens vers les alertes concernées. |
| `model_feedback` | Retours analystes | Verdicts `false_positive`/`confirmed` issus du statut d’alerte ; alimentent la supervision ML. |
| `notifications` | File de notifications | Messages générés par de vraies alertes `HIGH`/`CRITICAL` ; `delivery_status` = `not_configured` tant qu’aucun canal n’est configuré. |
| `playbooks` / `playbook_steps` | Procédures de réponse | Guides documentaires ordonnés, rattachés à un module et une sévérité minimale. |
| `audit_events` | Audit des actions sensibles | **Immuable** (voir ci-dessous). |

L’analyse d’URL est **sans état** : elle n’écrit ni dans `analysis_history` ni
dans `incidents` (la contrainte `module` n’autorise que `network`/`phishing`).

## Intégrité référentielle et index

- `PRAGMA foreign_keys = ON` est activé à chaque connexion.
- `analysis_history.user_id` et `incidents.owner_user_id` → `ON DELETE SET NULL`
  (supprimer un compte ne détruit pas l’historique ni les incidents).
- `incidents.history_id` → `UNIQUE`, `ON DELETE SET NULL`.
- `auth_sessions.user_id` et `incident_status_events.incident_id` → `ON DELETE CASCADE`.
- Index sur `analysis_history(created_at DESC)`,
  `events(timestamp DESC)`, `events(source_type, timestamp DESC)`,
  `events(severity, timestamp DESC)`,
  `incidents(owner_user_id, status, created_at DESC)`,
  `incident_status_events(incident_id, id)` et `audit_events(created_at DESC, id DESC)`.

## Audit immuable

`audit_events` est protégée par deux déclencheurs qui **interdisent UPDATE et
DELETE** (`RAISE(ABORT, 'audit events are immutable')`). Les actions journalisées
sont limitées à une liste fixe (voir `AUDIT_ACTIONS` dans
`backend/app/repositories/audit_repository.py`) : authentification
(`auth.*`), administration des comptes (`user.*`), cycle de vie SOC
(`incident.status_changed`, `alert.status_changed`, `alert.assigned`),
indicateurs (`ioc.created/updated/deleted`), règles et corrélation
(`rule.created/updated/deleted`, `correlation.run`) et playbooks
(`notification.dispatch`, `playbook.created/updated/deleted`). Les commentaires et tags sont journalisés
par ressource (`alert.comment_added`, `alert.tag_added/removed`,
`ioc.tag_added/removed`) sans copier leur contenu dans l’audit. `actor_user_id` n’a **pas** de clé
étrangère : la suppression d’un compte conserve ses lignes d’audit (traçabilité).
Aucun mot de passe, jeton ni secret n’y est stocké.

La liste des actions et des types de cible étant contrainte par un `CHECK`,
`initialize_database()` reconstruit la table `audit_events` (copie de toutes les
lignes, restauration des index et déclencheurs) lorsqu’une base existante
précède l’ajout d’une nouvelle action ou d’un nouveau `target_type`. Cette
migration est **idempotente et non destructive**.

## Confidentialité et rétention

Conformément à [data_policy.md](data_policy.md), la base **ne conserve jamais**
le texte analysé ni les caractéristiques réseau brutes — uniquement des
métadonnées de prédiction (module, classe, confiance, score, sévérité, modèle,
horodatage, `user_id`).

Exception explicite : les événements Suricata ingérés sont stockés comme
événements opérationnels avec leur EVE JSON brut et leurs champs normalisés.
L’accès API est limité aux Analyst/Admin; la purge utilise l’heure d’ingestion
et `RETENTION_DAYS`.

`purge_expired()` supprime les lignes plus anciennes que `RETENTION_DAYS` (1 à
30 jours, 30 par défaut) dans `analysis_history` **et** dans les artefacts SOC
éphémères : événements (heure d’ingestion), file `notifications` et
`correlation_findings` (ces dernières entraînent en cascade
`correlation_finding_alerts`). La purge globale s’exécute à l’initialisation et
après chaque analyse; l’ingestion exécute aussi la purge des événements avant
chaque insertion.

Ne sont **jamais** purgés automatiquement : `alerts`, `incidents`,
`incident_status_events`, `alert_status_events`, `model_feedback` et
`audit_events` (immuable) — ils constituent le dossier opérationnel du SOC et
suivent une conservation décidée par l’opérateur, pas la fenêtre de rétention des
métadonnées d’analyse.

## Inspection locale

```bash
sqlite3 database/togocyber.sqlite3 ".tables"
sqlite3 database/togocyber.sqlite3 "SELECT id, email, role FROM users;"
```

Pour repartir d’une base vide en local, arrêter l’API puis supprimer
`database/togocyber.sqlite3` ; elle sera recréée au prochain démarrage. Ne
jamais faire cela sur une installation partagée sans sauvegarde.

## Vers PostgreSQL (production)

La chaîne de connexion est désormais centralisée via **`DATABASE_URL`** (voir
`.env.example`). Aujourd’hui, seul le schéma `sqlite:///…` est pris en charge :
il définit le chemin du fichier SQLite. Une URL `postgresql://…` est **rejetée au
démarrage** avec un message explicite, afin de ne jamais laisser croire que
PostgreSQL est opérationnel tant que l’adaptateur n’existe pas. `TOGOCYBER_DB_PATH`
reste accepté comme repli lorsque `DATABASE_URL` est vide.

La couche de persistance est spécifique à SQLite (`sqlite3`, `executescript`,
`PRAGMA`, déclencheurs). Le passage réel à PostgreSQL demande :

1. un adaptateur de connexion (psycopg/SQLAlchemy) derrière une fabrique partagée ;
2. la conversion du schéma et des déclencheurs d’immuabilité (équivalents Postgres) ;
3. des migrations versionnées (Alembic) avant tout changement destructif ;
4. la gestion centralisée des secrets et l’externalisation de la limitation de
   débit (la protection anti brute-force actuelle est locale à la base).

Voir [deployment.md](deployment.md) et [security.md](security.md).
