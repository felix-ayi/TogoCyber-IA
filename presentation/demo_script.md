# Scénario de vidéo de démonstration (3–5 minutes)

1. **Introduction (30 s)** — préciser qu’il s’agit d’un prototype de recherche. Les scores visibles ont été mesurés sur des miroirs publics UNSW et des courriels anglais seulement ; ils ne valident pas CIC, le français togolais ou les SMS.
2. **Accueil / transparence (45 s)** — signaler l’avertissement, cookies essentiels et liens légaux.
3. **Analyse phishing (60 s)** — utiliser un exemple du corpus anglais public déjà chargé, sans donnée personnelle ; montrer résultat, niveau de confiance, facteurs LIME et prochaines étapes prudentes, puis télécharger le rapport JSON qui exclut le message fourni.
4. **Analyse réseau (60 s)** — utiliser un flux du test UNSW déjà chargé ; préciser que les ports de cette copie valent zéro, puis expliquer les facteurs SHAP et les vérifications recommandées. Rappeler que ces conseils ne confirment pas un incident.
5. **Historique et confidentialité (30 s)** — montrer seulement métadonnées, rappeler l’expiration 30 jours et que le rapport exporté ne contient ni texte soumis ni caractéristiques brutes du flux.
6. **API et clôture (30 s)** — ouvrir `/docs`, expliquer intégration et limites. L’assistant externe est désactivé tant qu’une clé API n’est pas configurée ; les analyses de modèles restent disponibles. Si des artefacts sont absents sur une autre installation, montrer la réponse 503 honnête, jamais un résultat inventé.
