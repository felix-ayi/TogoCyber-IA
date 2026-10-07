# Politique de données — démonstration

## Collecte et finalité

Le texte d’un SMS/e-mail/lien et les valeurs d’un flux soumis sont traités à la demande uniquement pour une prédiction. Ils ne sont pas écrits dans la base historique ni dans les journaux applicatifs. Le texte envoyé à l’assistant externe est transmis à OpenAI si cette option est configurée ; ne jamais soumettre d’information confidentielle. Le fournisseur applique ses propres conditions de traitement.

Le dashboard permet de télécharger un rapport JSON contenant le résultat, le score, le niveau de confiance et les explications. Pour réduire les divulgations accidentelles, il exclut le texte soumis et les caractéristiques brutes du flux. Le fichier est téléchargé sur l’appareil de l’utilisateur ; celui-ci reste responsable de sa conservation et de son partage.

Le dashboard fournit aussi des recommandations générales de prévention adaptées au résultat. Elles ne constituent ni une preuve technique ni un avis d’intervention ; pour un incident potentiel, suivez les procédures officielles de votre organisation et demandez une vérification humaine.

L’inspection d’URL examine localement sa structure uniquement : elle ne visite pas l’adresse, n’effectue aucune résolution DNS et ne contacte pas de service de réputation externe. L’URL fournie n’est ni enregistrée dans l’historique ni incluse dans un journal par ce service.

Les événements fournis manuellement à l’endpoint d’ingestion Suricata sont conservés dans SQLite sous forme normalisée **et** avec le `raw_event` EVE d’origine (maximum 64 KiB). Les rôles `Analyst` et `Admin` peuvent les consulter via l’API. Les événements expirent selon `RETENTION_DAYS` (30 jours par défaut); la purge s’exécute au démarrage et lors d’une ingestion. Ne transmettre que des journaux autorisés, minimisés et dépourvus de secrets ou de données personnelles inutiles.

## Historique et conservation

SQLite contient le module, la prédiction, le score et niveau de confiance, l'identifiant interne du compte propriétaire et l'horodatage. Les entrées expirent au plus tard 30 jours après l'analyse ; purge à l'initialisation et lors de chaque enregistrement. Le fichier se trouve à `TOGOCYBER_DB_PATH` (par défaut `database/togocyber.sqlite3`). L'administrateur peut effacer l'historique en supprimant le fichier de base de données lorsque l'application est arrêtée.

Les comptes conservent l'adresse e-mail, un hash PBKDF2 du mot de passe, le rôle et l'état du compte. Les sessions gardent uniquement le hash de l'identifiant du jeton, son expiration et son statut de révocation. Les échecs de connexion sont limités à cinq en quinze minutes par empreinte d'adresse cliente ; l'adresse IP brute n'est pas conservée.

Les incidents créés pour les scores `HIGH` ou `CRITICAL` conservent le module, la classe prédite, le score, la sévérité, l'état, l'identifiant du compte propriétaire et un journal des transitions comportant l'identifiant du compte opérateur. Ils ne sont pas supprimés par la purge des analyses après 30 jours ; dans ce prototype, leur suppression nécessite l'effacement de la base par l'administrateur. Définir une durée de conservation et un processus d'effacement avant toute utilisation réelle.

## Droits, jeux et annotations

Pour exercer une demande d’effacement concernant le déploiement, contacter son administrateur. Le gabarit d’annotation local ne contient que les noms de colonnes. Collecter 50–100 exemples togolais réels seulement avec autorisation/consentement, minimiser les identifiants, anonymiser, documenter provenance et licence, faire valider chaque étiquette humainement. La copie locale du CSV et les données sont ignorées par Git et Docker. Le script de préparation refuse les entrées sans consentement, provenance ou annotation `togolese_french`; le fichier final ne garde que le texte nécessaire et le label. Ne pas déposer de données personnelles ou corpus sous licence dans Git.

## Avertissement de recherche

Les résultats ne remplacent ni les équipes de sécurité ni les canaux officiels des opérateurs. Les fausses alertes et menaces manquées sont possibles.