# Architecture

```text
Streamlit (frontend/app.py)
        │ HTTP JSON, TOGOCYBER_API_URL
        ▼
FastAPI (backend/app/main.py, /api/v1)
   ├── /network/analyze ── canonical features ── sklearn Pipeline ── SHAP
   ├── /phishing/analyze ─ TF-IDF Pipeline ──────────────── LIME
   ├── /assistant/ask ─── OpenAI HTTPS (optional, no fallback)
   └── /history ───────── SQLite (metadata only, TTL ≤ 30 days)
```

## Schémas et dépendances

Le schéma réseau versionné est défini dans `ml/common/preprocessing.py` et consommé par l’import CIC/UNSW, les pipelines, l’API et le formulaire dashboard. Les neuf nombres finis sont `duration` (secondes), octets/paquets source et destination, ports, identifiant protocole et `flow_rate` (paquets/s). Toute variable manquante/inconnue est refusée. CIC (`Flow Duration`, `Total Length of Fwd Packets`, etc.) est projeté vers ce contrat ; durée CIC convertie de microsecondes en secondes. UNSW utilise `dur`, `sbytes`, `dbytes`, etc. Le chargeur accepte un fichier ou un répertoire de CSV CIC quotidiens / UNSW train-test. Cette projection ne corrige pas toutes les divergences de collecte et de distribution.

Le contrat phishing est CSV `text,label`, labels normalisés vers `legitimate=0` et `phishing=1`. Les endpoints vérifient limites et types avec Pydantic. OpenAPI documente les requêtes FastAPI.

L’entraînement scinde stratifié en 60 % apprentissage, 20 % validation de modèle, 20 % test tenu à l’écart. Les transformations ajustées (imputation, TF-IDF) sont dans les pipelines. Le choix se fait sur F1 de validation seulement ; le test n’intervient pas dans cette sélection. Les paramètres d’équilibrage XGBoost sont calculés sur le train.

## Artefacts

Les pipelines complets sont sérialisés avec joblib dans `models/artifacts/`; le registre conserve le choix, les variables et métriques issues du test. Aucun modèle entraîné n’est livré. Le chargement d’un artefact manquant entraîne une réponse HTTP 503 explicite.

## SQLite

`analysis_history` stocke exclusivement module, classe prédite, score de confiance, niveau et date. Le texte et les caractéristiques de flux ne sont jamais persistés. Purge des entrées âgées au plus tard lors de l’initialisation et des analyses. Le fichier peut être déplacé via `TOGOCYBER_DB_PATH`.

## Sécurité et limites

Aucun endpoint ne scanne un hôte ou un réseau. CORS est limité par `CORS_ALLOWED_ORIGINS`. Secrets fournis par variables d’environnement. L’API de démonstration n’a pas d’authentification : déployer derrière une passerelle contrôlée, TLS, quotas et authentification avant tout usage externe/B2B.