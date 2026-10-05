# Politique de données — démonstration

## Collecte et finalité

Le texte d’un SMS/e-mail/lien et les valeurs d’un flux soumis sont traités à la demande uniquement pour une prédiction. Ils ne sont pas écrits dans la base historique ni dans les journaux applicatifs. Le texte envoyé à l’assistant externe est transmis à OpenAI si cette option est configurée ; ne jamais soumettre d’information confidentielle. Le fournisseur applique ses propres conditions de traitement.

## Historique et conservation

SQLite contient le module, la prédiction, le score et niveau de confiance, et l’horodatage. Les entrées expirent au plus tard 30 jours après l’analyse ; purge à l’initialisation et lors de chaque enregistrement. Le fichier se trouve à `TOGOCYBER_DB_PATH` (par défaut `database/togocyber.sqlite3`). L’administrateur peut effacer l’historique en supprimant le fichier de base de données lorsqu’il est arrêté.

## Droits, jeux et annotations

Pour exercer une demande d’effacement concernant le déploiement, contacter son administrateur. Le gabarit d’annotation local ne contient que les noms de colonnes. Collecter 50–100 exemples togolais réels seulement avec autorisation/consentement, minimiser les identifiants, anonymiser, documenter provenance et licence, faire valider chaque étiquette humainement. La copie locale du CSV et les données sont ignorées par Git et Docker. Le script de préparation refuse les entrées sans consentement, provenance ou annotation `togolese_french`; le fichier final ne garde que le texte nécessaire et le label. Ne pas déposer de données personnelles ou corpus sous licence dans Git.

## Avertissement de recherche

Les résultats ne remplacent ni les équipes de sécurité ni les canaux officiels des opérateurs. Les fausses alertes et menaces manquées sont possibles.