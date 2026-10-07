# Architecture

```text
Streamlit (frontend/app.py)
        │ HTTP JSON + short-lived Bearer token, TOGOCYBER_API_URL
        ▼
FastAPI (backend/app/main.py, /api/v1)
   ├── /auth/* ───────── PBKDF2 passwords, signed/revocable JWT sessions, RBAC
   ├── /network/analyze ── canonical features ── sklearn Pipeline ── SHAP
   ├── /phishing/analyze ─ TF-IDF Pipeline ──────────────── LIME
   ├── /url/analyze ────── URL syntax/structure checks (no DNS, HTTP fetch, or persistence)
        ├── /events/ingest/suricata ─ EVE JSON → normalized event → SQLite (manual POST)
   ├── /assistant/ask ─── OpenAI HTTPS (optional, no fallback)
   ├── Risk Engine ────── probability → bounded score/severity/recommendations
   ├── /history ───────── SQLite (per-user result/model metadata, TTL ≤ 30 days)
   └── /incidents ─────── SQLite (high-risk queue, role-scoped status workflow/audit)
```

L’ingestion Suricata est un premier adaptateur HTTP unitaire. Il ne collecte pas les
journaux lui-même et son stockage n’alimente pas encore le moteur de règles, les
alertes ou les corrélations.

## Schémas et dépendances

Le schéma réseau versionné est défini dans `ml/common/preprocessing.py` et consommé par l’import CIC/UNSW, les pipelines, l’API et le formulaire dashboard. Les neuf nombres finis sont `duration` (secondes), octets/paquets source et destination, ports, identifiant protocole et `flow_rate` (paquets/s). Toute variable manquante/inconnue est refusée. CIC (`Flow Duration`, `Total Length of Fwd Packets`, etc.) est projeté vers ce contrat ; durée CIC convertie de microsecondes en secondes. UNSW utilise `dur`, `sbytes`, `dbytes`, etc. Le chargeur accepte un fichier ou un répertoire de CSV CIC quotidiens / UNSW train-test. Cette projection ne corrige pas toutes les divergences de collecte et de distribution.

Le contrat phishing est CSV `text,label`, labels normalisés vers `legitimate=0` et `phishing=1`. Les endpoints vérifient limites et types avec Pydantic. OpenAPI documente les requêtes FastAPI.

L’entraînement scinde stratifié en 60 % apprentissage, 20 % validation de modèle, 20 % test tenu à l’écart. Les transformations ajustées (imputation, TF-IDF) sont dans les pipelines. Le choix se fait sur F1 de validation seulement ; le test n’intervient pas dans cette sélection. Les paramètres d’équilibrage XGBoost sont calculés sur le train.

## Artefacts

Les pipelines complets sont sérialisés avec joblib dans `models/artifacts/`; le registre conserve le choix, les variables et métriques issues du test. Aucun modèle entraîné n’est livré. Le chargement d’un artefact manquant entraîne une réponse HTTP 503 explicite.

## SQLite

`analysis_history` stocke exclusivement module, classe prédite, score de confiance, niveau, identifiant utilisateur, score de risque, sévérité, identifiant/version de modèle et date. Le texte et les caractéristiques de flux ne sont jamais persistés. L'ajout de colonnes est une migration additive exécutée au démarrage ; les lignes préexistantes restent conservées sans propriétaire et sans valeurs ML antérieures, et ne sont visibles que dans les vues Admin/Analyst. Purge des entrées âgées au plus tard lors de l’initialisation et des analyses. Le fichier peut être déplacé via `TOGOCYBER_DB_PATH`.

`events` stocke les événements Suricata normalisés et leur EVE JSON brut (64 KiB
maximum par événement). `event_id` est une empreinte SHA-256 canonique et clé
primaire, ce qui rend le dépôt idempotent. Les événements sont consultables par les
rôles Analyst/Admin et supprimés selon `RETENTION_DAYS`, au démarrage et lors
d’une nouvelle ingestion. La purge utilise l’heure d’ingestion, non l’horodatage
fourni par la source.

`users`, `auth_sessions` et `auth_login_attempts` conservent les comptes, les identifiants de session hachés et des empreintes d'identifiants clients pour limiter les échecs de connexion. Aucun mot de passe, jeton Bearer ou adresse IP brute n'est écrit dans ces tables.

Les analyses authentifiées de sévérité `HIGH` ou `CRITICAL` créent, dans la même transaction, un incident sans contenu brut. `incidents` conserve le compte propriétaire, les métadonnées de risque et l'état courant ; `incident_status_events` enregistre chaque état antérieur/nouveau et l'identifiant du compte opérateur. Les comptes User ne voient que leurs incidents ; Analyst/Admin consultent et gèrent la file entière. Les incidents et leur journal ne sont pas supprimés avec l'expiration à 30 jours de l'historique d'analyse ; ils demeurent jusqu'à suppression de la base, une limite de conservation à définir avant tout déploiement réel.

Le moteur de risque arrondit la probabilité positive du modèle sur 100 puis mappe les seuils documentés vers une sévérité. Les contributions SHAP/LIME sont exposées comme indicateurs explicatifs, jamais comme indicateurs de compromission vérifiés. Les recommandations sont défensives et ne transforment pas un score en preuve d'incident.

L’inspection d’URL est un contrôle heuristique distinct, sans appel réseau : elle valide l’hôte et examine les identifiants intégrés, punycode, IP littérales, raccourcisseurs, ports, sous-domaines et motifs textuels. Le score de présentation n’est pas calibré ; ni l’URL ni ses composants ne sont enregistrés. Aucun verdict de réputation n’est prétendu.

## Sécurité et limites

L'inscription publique attribue uniquement le rôle `User`. `Analyst` et `Admin` sont provisionnés par un administrateur ; un Admin initial est créé uniquement si les variables bootstrap sont configurées. Les routes d'analyse et l'historique exigent une session signée d'une durée de 30 minutes, révocable au logout. Aucun endpoint ne scanne un hôte ou un réseau. CORS est limité par `CORS_ALLOWED_ORIGINS`. Secrets fournis par variables d’environnement. SQLite et le limiteur par adresse cliente conviennent au prototype local, pas à un déploiement multi-tenant distribué sans architecture partagée de production. Voir `docs/security.md`.