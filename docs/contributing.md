# Contribuer

Merci de faire évoluer TogoCyber AI de façon **incrémentale et honnête** : on
améliore l’existant, on ne recrée pas une architecture parallèle et on ne simule
jamais un résultat.

## Environnement de développement

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt   # requirements.txt + pytest, ruff, bandit, pip-audit
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
python scripts\setup.py
```

`requirements-dev.txt` ajoute les outils de qualité (pytest, ruff, bandit,
pip-audit) au-dessus de `requirements.txt`. Ne jamais commiter de vraie clé dans
`.env` (ignoré par Git) ; utiliser `.env.example` pour les nouveaux placeholders.

## Lancer les tests

```powershell
python -m pytest            # recommandé
python -m unittest discover -s tests -v   # équivalent (tests écrits en unittest)
```

La suite **n’exige pas de modèles entraînés** : le chargement des `.joblib` est
bouchonné (les artefacts ne sont pas livrés dans Git). Elle doit rester verte sur
un checkout propre. Ajouter des cas négatifs (jeton invalide, entrée malformée,
endpoint non autorisé, fichier trop volumineux) à côté des cas passants.

## Style et qualité

- **Lint** : `ruff check .` — la configuration (`pyproject.toml`,
  `[tool.ruff.lint]`) ne retient que `E9` (erreurs de syntaxe) et `F`
  (pyflakes : imports inutilisés, noms indéfinis). Les règles purement
  cosmétiques ne sont pas imposées pour éviter un reformatage massif ; ne pas
  les activer sans discussion.
- **SAST** : `bandit -q -r backend ml -x '*/__pycache__/*'` — doit rester sans
  finding. Un faux positif justifié se marque d’un `# nosec <ID>` **sur la ligne
  signalée**, avec une explication en commentaire ordinaire juste au-dessus
  (ne pas mettre de texte libre après l’ID, bandit le prendrait pour d’autres
  identifiants de test).
- Préférer modifier le fichier existant responsable plutôt que créer
  `app_new.py`, `*_v2.py`, etc. Éviter les fichiers énormes ; refactoriser
  proprement si besoin, sans changer le comportement.

## Intégration continue

`.github/workflows/ci.yml` exécute, dans l’ordre : **Lint → Tests → Sécurité →
Build Docker** (chaque étape dépend de la précédente). Aucun déploiement
automatique en production : le build Docker ne fait que vérifier que l’image
compile.

- `bandit` est **bloquant**.
- `pip-audit` est **informatif** (`continue-on-error`) : `requirements.txt`
  n’est pas épinglé, un avis sur une dépendance transitive ne doit pas bloquer
  un travail sans lien. Traiter le rapport en épinglant/mettant à jour
  délibérément.

Une PR doit passer la CI avant fusion.

## Données et modèles

- Ne **jamais** commiter : `.env`, bases SQLite, `*.joblib`,
  `models/metadata/model_registry.json`, `data/raw/*` (sauf README), données
  d’annotation non consenties. Ces exclusions `.gitignore` ne doivent pas être
  retirées sans revue.
- Les datasets de démonstration sont téléchargés et vérifiés par empreinte
  SHA-256 via `scripts/download_demo_datasets.py`. Documenter la provenance et
  la licence ; ne pas prétendre qu’un modèle est validé sur du trafic réel
  togolais quand il ne l’est pas (voir [limitations.md](limitations.md) et
  [ml_methodology.md](ml_methodology.md)).
- Réentraîner un modèle uniquement avec une raison documentée : conserver les
  métriques avant/après, vérifier l’absence de fuite train/test, versionner.

## Base de données

Le schéma existe à deux endroits à garder synchrones : `database/schema.sql`
(référence) et la constante `SCHEMA_SQL` dans
`backend/app/models/database_models.py` (appliquée au démarrage). Les migrations
restent additives et non destructives. Détails dans [database.md](database.md).

## Sécurité

Relire [security.md](security.md) avant toute touche à l’authentification, aux
uploads, au CORS ou aux appels externes. Ne pas exposer de stack trace en
production, ne pas journaliser mots de passe/jetons/secrets, valider les entrées
avec Pydantic, et ne jamais visiter aveuglément une URL fournie par un
utilisateur.
