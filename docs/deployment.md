# Déploiement et exécution

## Local

Voir le README : environnement Python 3.11+, installation `requirements.txt`, démarrer `uvicorn backend.app.main:app` puis `streamlit run frontend/app.py`. `scripts/setup.py` vérifie les paquets et crée les dossiers de sortie.

Les deux entraîneurs et les notebooks exigent les CSV source et ne fabriquent pas de résultats. Le CIC officiel demande un formulaire d’inscription à remplir directement par l’utilisateur ; cet outil ne l’automatise pas et ne transmet aucun identifiant.

## Docker Compose

Depuis la racine, `docker compose up --build` publie le dashboard (8501) et API (8000) sur l’interface locale uniquement. L’historique persiste dans un volume Docker. Placer des modèles entraînés dans `models/artifacts` (lecture seule dans le conteneur API). Configurer `OPENAI_API_KEY` dans l’environnement local, jamais dans le code. Les téléchargements de corpus ne sont pas montés par défaut.

Le point d’entrée phishing borne LIME à 200 échantillons sur au plus 2 000 caractères et limite à deux le nombre d’analyses simultanées par processus ; la prédiction continue d’utiliser le texte complet jusqu’à 20 000 caractères. Les demandes concurrentes supplémentaires reçoivent HTTP 429. Cette protection locale ne constitue pas une limitation de débit distribuée.

## Production

Cette configuration est une démonstration : endpoints sans authentification, aucune isolation multi-tenant, quotas, TLS ou supervision. Avant toute exposition, utiliser une terminaison TLS et passerelle authentifiée, appliquer des limites de débit partagées et de taille des requêtes, configurer les secrets de façon gérée, sauvegarder/expirer SQLite, contrôler les licences des données et modèles, et vérifier les permissions du système de fichiers. La limite de concurrence phishing en mémoire ne remplace pas ces contrôles.

## Dossiers sensibles

`.env`, `data/raw`, les bases SQLite et les modèles sérialisés sont ignorés par Git. N’enlevez pas ces exclusions sans revue. Charger des modèles joblib de provenance inconnue peut exécuter du code Python ; ne charger que des artefacts de confiance.