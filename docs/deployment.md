# Déploiement et exécution

## Local

Voir le README : environnement Python 3.11+, installation `requirements.txt`, démarrer `uvicorn backend.app.main:app` puis `streamlit run frontend/app.py`. `scripts/setup.py` vérifie les paquets et crée les dossiers de sortie.

Les deux entraîneurs et les notebooks exigent les CSV source et ne fabriquent pas de résultats. Le CIC officiel demande un formulaire d’inscription à remplir directement par l’utilisateur ; cet outil ne l’automatise pas et ne transmet aucun identifiant.

## Docker Compose

Depuis la racine, `docker compose up --build` publie le dashboard (8501) et API (8000). L’historique persiste dans un volume Docker. Placer des modèles entraînés dans `models/artifacts` (lecture seule dans le conteneur API). Configurer `OPENAI_API_KEY` dans l’environnement local, jamais dans le code. Les téléchargements de corpus ne sont pas montés par défaut.

## Production

Cette configuration est une démonstration : endpoints sans authentification, aucune isolation multi-tenant, quotas, TLS ou supervision. Avant exposition, utiliser une terminaison TLS et passerelle authentifiée, limiter tailles/fréquences, configurer secrets de façon gérée, sauvegarder/expirer SQLite, contrôler licences des données et modèles, et vérifier permissions du système de fichiers.

## Dossiers sensibles

`.env`, `data/raw`, les bases SQLite et les modèles sérialisés sont ignorés par Git. N’enlevez pas ces exclusions sans revue. Charger des modèles joblib de provenance inconnue peut exécuter du code Python ; ne charger que des artefacts de confiance.