# Déploiement et exécution

## Local

Voir le README : environnement Python 3.11+, installation `requirements.txt`, démarrer `uvicorn backend.app.main:app` puis `streamlit run frontend/app.py`. `scripts/setup.py` vérifie les paquets et crée les dossiers de sortie.

Les deux entraîneurs et les notebooks exigent les CSV source et ne fabriquent pas de résultats. Le CIC officiel demande un formulaire d’inscription à remplir directement par l’utilisateur ; cet outil ne l’automatise pas et ne transmet aucun identifiant.

## Docker Compose

Depuis la racine, copier `.env.example` vers `.env`, définir une `AUTH_SECRET_KEY` aléatoire d'au moins 32 caractères et lancer `docker compose up --build`. Le dashboard (8501) et l’API (8000) sont publiés sur l’interface locale uniquement. Pour créer le premier administrateur, renseigner également `BOOTSTRAP_ADMIN_EMAIL` et `BOOTSTRAP_ADMIN_PASSWORD` (11 caractères minimum) avant le premier démarrage ; supprimer ces variables après création. L'historique, les utilisateurs et les sessions sont conservés dans le volume SQLite. Placer des modèles entraînés dans `models/artifacts` (lecture seule dans le conteneur API). Configurer `OPENAI_API_KEY` dans l’environnement local, jamais dans le code. Les téléchargements de corpus ne sont pas montés par défaut.

Sans `AUTH_SECRET_KEY`, le mode local génère une clé éphémère à chaque démarrage : les jetons existants deviennent invalides au redémarrage. Définir une clé persistante est obligatoire pour une installation durable ou multi-processus.

Le point d’entrée phishing borne LIME à 200 échantillons sur au plus 2 000 caractères et limite à deux le nombre d’analyses simultanées par processus ; la prédiction continue d’utiliser le texte complet jusqu’à 20 000 caractères. Les demandes concurrentes supplémentaires reçoivent HTTP 429. Cette protection locale ne constitue pas une limitation de débit distribuée.

## Production

Cette configuration est une démonstration : endpoints sans authentification, aucune isolation multi-tenant, quotas, TLS ou supervision. Avant toute exposition, utiliser une terminaison TLS et passerelle authentifiée, appliquer des limites de débit partagées et de taille des requêtes, configurer les secrets de façon gérée, sauvegarder/expirer SQLite, contrôler les licences des données et modèles, et vérifier les permissions du système de fichiers. La limite de concurrence phishing en mémoire ne remplace pas ces contrôles.

## Dossiers sensibles

`.env`, `data/raw`, les bases SQLite et les modèles sérialisés sont ignorés par Git. N’enlevez pas ces exclusions sans revue. Charger des modèles joblib de provenance inconnue peut exécuter du code Python ; ne charger que des artefacts de confiance.