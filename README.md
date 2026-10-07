# TogoCyber AI

Prototype de recherche pour la détection de menaces réseau et de phishing/smishing, avec explications SHAP/LIME, API FastAPI et interface Streamlit. Conçu pour la sensibilisation au Togo ; ce n’est pas un produit de sécurité certifié.

> **Démo locale entraînée et testée sur des sources publiques épinglées.** Les scores de cette démonstration ne valident pas le cahier des charges final : le détecteur réseau utilise un miroir UNSW-NB15, le détecteur de texte un corpus de courriels anglais. Ni CIC-IDS2017, ni français/SMS togolais, ni généralisation CIC→UNSW ne sont évalués ici. Les mesures réelles et leurs limites sont consignées dans [docs/demo_results.md](docs/demo_results.md) ; ne les interprétez pas comme une garantie de sécurité.

## Arborescence

```text
TogoCyber-AI/
├── backend/                 # API FastAPI, schémas, services et historique SQLite
├── database/                # Schéma SQLite et données locales ignorées par Git
├── data/
│   ├── annotations/         # Gabarit vide pour annotations togolaises consenties
│   └── raw/                 # Placez ici les CSV téléchargés légalement
├── docs/                    # Architecture, données, base, API, limites, prompt, déploiement, contribution
├── frontend/                # Dashboard Streamlit, composants et vues légales
├── ml/
│   ├── common/               # Schéma réseau partagé, métriques, EDA, artefacts
│   ├── network/              # Random Forest, XGBoost, SHAP et généralisation UNSW
│   ├── phishing/             # TF-IDF, LR, Naive Bayes, LIME et biais linguistique
│   └── assistant/            # Prompt et client d’assistance
├── models/                   # Registre ; les modèles .joblib ne sont pas livrés
├── notebooks/                # EDA, modélisation, XAI et généralisation
├── presentation/             # Slides autonomes et scénario de démonstration
├── scripts/                  # Vérification, entraînement et évaluation
└── tests/                    # Tests de contrats et de comportement API
```

## Stack

Python 3.11+, pandas, NumPy, scikit-learn, XGBoost, imbalanced-learn, matplotlib, seaborn, SHAP, LIME, FastAPI/uvicorn, Pydantic, Streamlit et SQLite. Le service assistant utilise l’API OpenAI via HTTPS et nécessite une clé optionnelle. SQLite est utilisé via le module standard `sqlite3`.

## Installation et démarrage local (PowerShell)

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
python scripts\setup.py
```

Dans deux terminaux PowerShell depuis la racine du dépôt :

```powershell
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

```powershell
streamlit run frontend\app.py
```

- Dashboard : <http://localhost:8501>
- Documentation API interactive : <http://localhost:8000/docs>
- Santé API : <http://localhost:8000/api/v1/health>

Sans modèle entraîné, les endpoints d’analyse répondent HTTP 503 ; c’est attendu, pas un résultat simulé.

Si les ports 8000/8501 sont déjà occupés, utiliser deux terminaux PowerShell :

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8010
```

```powershell
$env:TOGOCYBER_API_URL = "http://127.0.0.1:8010"
.\.venv\Scripts\python.exe -m streamlit run frontend\app.py --server.port 8502
```

Puis ouvrir <http://localhost:8502>.

## Données puis entraînement

1. Pour charger les sources publiques épinglées utilisées par le parcours de démonstration : `python scripts\download_demo_datasets.py`. Le script vérifie leurs empreintes SHA-256 avant de les accepter. Lisez d’abord les [conditions et licences indiquées par les cartes des sources](data/raw/README.md) ; ces miroirs ne sont pas une autorisation de redistribution ou d’usage commercial. Le téléchargement CIC officiel exige un formulaire d’inscription ; l’application ne le contourne pas.
2. Les fichiers de démonstration sont placés dans `data/raw/unsw_nb15/train.csv`, `data/raw/unsw_nb15/test.csv` et `data/raw/phishing/Phishing_Email.csv`. Le mirror UNSW nettoyé ne fournit pas les ports source/destination ; leur valeur est mise à zéro pour l’entraînement démo. Pour le parcours de recherche conforme au cahier des charges, placez les données CIC dans `data/raw/cic_ids2017/` et un corpus phishing autorisé (français/togolais inclus uniquement avec annotation et consentement) dans `data/raw/phishing.csv`.
3. Parcours de démonstration immédiate : `python scripts\train_network.py --dataset unsw --data data\raw\unsw_nb15\train.csv --test-data data\raw\unsw_nb15\test.csv` puis `python scripts\train_phishing.py --data data\raw\phishing\Phishing_Email.csv`. Le premier sélectionne le modèle sur validation et rapporte séparément le test UNSW fourni ; il n’évalue pas une généralisation CIC→UNSW. Le corpus phishing est constitué de courriels anglais et ne valide ni le français, ni les SMS togolais.
4. Parcours de recherche : exécutez les notebooks 01–06 dans l’ordre, puis le notebook 07 facultatif de biais après annotation représentative ; ou entraînez le réseau avec `python scripts\train_network.py --data data\raw\cic_ids2017` et le texte avec `python scripts\train_phishing.py --data data\raw\phishing.csv`. L’entraînement réseau utilise par défaut un échantillon stratifié de 250 000 lignes ; `--max-rows 0` traite le dataset entier. CIC-IDS2017 reste le chemin par défaut du code de recherche.
5. Pour intégrer 50–100 exemples togolais réellement recueillis, annotés et consentis : copier `data/annotations/togolese_examples.template.csv` vers `data/annotations/togolese_examples.csv`, compléter cette copie locale ignorée par Git, puis exécuter `python scripts\prepare_phishing_data.py` ; entraîner avec `--data data\raw\phishing_with_togolese.csv`. Le script refuse les exemples sans consentement ou provenance et n’écrase jamais le fichier de sortie existant.
6. Les modèles retenus sont écrits dans `models/artifacts/` et les métriques issues du jeu fourni dans `models/metadata/model_registry.json`. Les modèles et CSV sont exclus de Git.
7. L’analyse de biais exige un jeu de test séparé avec `language_group` (`standard_french` ou `togolese_french`) et deux classes par groupe.

Le contrat API réseau utilise les variables : `duration` (secondes), `src_bytes`, `dst_bytes`, `src_packets`, `dst_packets`, `src_port`, `dst_port`, `protocol_number` (TCP 6, UDP 17, ICMP 1), `flow_rate` (paquets/seconde). Cette projection commune facilite l’essai CIC→UNSW mais ne supprime pas le décalage de domaine ; les métriques cross-dataset doivent être interprétées prudemment.

## Ingestion Suricata (premier connecteur)

Un utilisateur `Analyst` ou `Admin` peut soumettre un objet EVE JSON à `POST /api/v1/events/ingest/suricata`. L’événement est validé, normalisé, stocké dans SQLite et dédoublonné par empreinte de contenu; les événements sont consultables via `GET /api/v1/events`. Cette API n’écoute pas un fichier ou socket Suricata, ne surveille pas de journal et ne transforme pas encore ces événements en alertes/incidents. Voir [docs/api.md](docs/api.md).

## Tests

```powershell
python -m pytest
```

`python -m unittest discover -s tests -v` fonctionne aussi (tests écrits en `unittest`). La suite n’exige pas de modèles entraînés : le chargement des `.joblib` est bouchonné. Une intégration continue (`.github/workflows/ci.yml`) enchaîne lint (ruff), tests (pytest), contrôles de sécurité (bandit bloquant, pip-audit informatif) et build Docker. Les tests de contrat ne prétendent pas évaluer la qualité des modèles sur de vraies données. Voir [docs/limitations.md](docs/limitations.md), [docs/deployment.md](docs/deployment.md) et [docs/contributing.md](docs/contributing.md).

## Base de données

SQLite local (`database/togocyber.sqlite3`, ignoré par Git), initialisé de façon idempotente avec des migrations additives non destructives ; historique et événements ingérés purgés selon `RETENTION_DAYS`. La chaîne de connexion est centralisée via `DATABASE_URL` (seul `sqlite:///…` est câblé ; une URL `postgresql://…` est rejetée au démarrage tant que l’adaptateur Postgres n’existe pas). Outre l’authentification et l’historique, la base porte les tables SOC : événements Suricata, alertes, incidents, IOC, règles de corrélation, retours modèles, notifications et playbooks. Le schéma est documenté dans [docs/database.md](docs/database.md).


## Confidentialité

Le texte et les caractéristiques réseau des analyses unitaires ne sont pas conservés dans leur historique. Le pipeline Suricata conserve en revanche le `raw_event` EVE JSON et les champs normalisés dans `events`, accessibles aux rôles SOC et purgés selon `RETENTION_DAYS` (30 jours par défaut). Ne soumettez que des événements autorisés et minimisés. L'historique des analyses garde le module, la classe prédite, la confiance, l'identifiant interne du propriétaire et l'horodatage. L'assistant OpenAI ne fonctionne que si `OPENAI_API_KEY` est configurée ; son message est envoyé au fournisseur et soumis à ses conditions. Ne saisissez aucune information confidentielle.

Pages de confidentialité, conditions d’utilisation, cookies, transparence et avertissements sont accessibles dans le menu du dashboard. Voir [docs/data_policy.md](docs/data_policy.md).

## Comptes et authentification

L'API et le dashboard utilisent le même login backend : mot de passe haché PBKDF2-HMAC-SHA256, jeton Bearer signé valable 30 minutes, session révocable et permissions vérifiées côté API. L'inscription publique crée uniquement des comptes `User`; elle ne peut pas se donner des droits SOC ou Admin.

### Créer le premier administrateur

1. Copier `.env.example` vers `.env` : `Copy-Item .env.example .env` (PowerShell).
2. Dans `.env`, définir `AUTH_SECRET_KEY` avec une valeur aléatoire d’au moins 32 caractères.
3. Définir `BOOTSTRAP_ADMIN_EMAIL` et un `BOOTSTRAP_ADMIN_PASSWORD` unique et fort (minimum technique : 11 caractères; privilégier au moins 16).
4. Démarrer l’API; au premier démarrage, elle crée ce compte une seule fois avec le rôle `Admin`.
5. Ouvrir le dashboard et se connecter avec ces identifiants. Retirer ensuite les deux variables `BOOTSTRAP_ADMIN_*` de `.env`; le compte créé reste en base.

Ne jamais mettre ces secrets dans le code, un dépôt Git, une capture ou un ticket. Si le compte Admin existe déjà, changer `BOOTSTRAP_ADMIN_PASSWORD` ne réinitialise pas son mot de passe; un Admin connecté peut réinitialiser les comptes gérés via l’interface/API.

### Rôles existants

- `Admin` : toutes les pages, dont SOC, audit et gestion des utilisateurs; peut créer des comptes `Analyst` et `User`.
- `Analyst` : pages SOC et triage, sans audit ni gestion des utilisateurs.
- `User` : outils d’analyse et accès à son propre historique/incidents; pas de file SOC.

Les rôles `SUPER_ADMIN`, `SOC_ANALYST`, `THREAT_HUNTER`, `AUDITOR` et `VIEWER` ne sont pas implémentés. Le backend ne les accepte pas et les traite comme non autorisés; le menu seul n’accorde jamais de permissions. Voir [docs/api.md](docs/api.md) et [docs/deployment.md](docs/deployment.md).