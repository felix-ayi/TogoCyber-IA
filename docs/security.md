# Sécurité applicative — état du prototype

## Authentification et rôles

- Inscription publique, rôle `User` imposé côté serveur.
- Mots de passe hachés avec PBKDF2-HMAC-SHA256, sel aléatoire de 16 octets et 600 000 itérations.
- Jetons HMAC-SHA256 de 30 minutes ; identifiant de session stocké sous forme de hash et révocable à la déconnexion.
- Les routes d'analyse, d'assistance et d'historique sont authentifiées.
- `User` consulte son propre historique ; `Analyst` et `Admin` peuvent consulter l'historique global ; seul `Admin` gère les comptes Analyst/User.
- Les résultats `HIGH`/`CRITICAL` créent des incidents sans conserver les contenus analysés. User ne voit que ses incidents ; Analyst/Admin voient la file entière et seuls ces deux rôles peuvent faire évoluer les états. Chaque transition est journalisée avec l'identifiant du compte opérateur.
- Cinq échecs de connexion par empreinte de client sur une fenêtre de 15 minutes provoquent une réponse 429. Les empreintes sont protégées par HMAC avec le secret d'authentification.
- Le premier Admin est facultatif et se crée via `BOOTSTRAP_ADMIN_EMAIL` et `BOOTSTRAP_ADMIN_PASSWORD` au premier démarrage. Le mot de passe doit faire au moins 11 caractères ; les deux variables doivent être retirées après création. Une rotation du mot de passe de bootstrap ne modifie pas un compte déjà créé.

## Stockage et secrets

`AUTH_SECRET_KEY` doit être une valeur aléatoire d'au moins 32 caractères pour les installations durables. En mode local sans cette variable, le serveur génère une clé éphémère ; les sessions deviennent invalides au prochain redémarrage. Ne jamais versionner `.env`.

SQLite reçoit une migration additive du schéma d'historique : les anciennes analyses ne sont pas supprimées. Elles restent sans propriétaire et ne sont pas visibles par un compte `User`.

Le score de risque est une normalisation de la probabilité positive du modèle (arrondie à 0–100) ; les catégories de sévérité sont des seuils de présentation, non une validation externe de la menace.

## Limites non résolues avant une exposition publique

Les incidents ne sont pas purgés à l'expiration de l'historique et persistent tant que la base existe ; une politique de conservation automatisée doit être définie avant tout déploiement réel.

Cette version reste une démonstration et n'est pas une plateforme SOC de production. Elle n'a pas encore de PostgreSQL/migrations gérées, d'audit log général (seul le journal de transitions d'incidents existe), d'analyse d'URL, de rate limiting global ou de stockage de sessions distribué. Le limiteur de connexion est adapté à une instance utilisant le même fichier SQLite ; derrière un proxy, il faut transmettre l'identité cliente uniquement depuis des proxys de confiance et configurer la protection côté passerelle. Une clé partagée persistante et une base transactionnelle adaptée sont nécessaires en multi-instance. TLS, durcissement du proxy, sauvegardes, monitoring et procédure de rotation des secrets restent à déployer.

Les limites ML et de provenance des données sont décrites dans [limitations](./limitations.md), [résultats de démonstration](./demo_results.md) et [déploiement](./deployment.md).
