# Données brutes (non versionnées)

Placer ici des fichiers obtenus légalement. Le parcours de démonstration fournit un téléchargeur reproductible :

```powershell
python scripts\download_demo_datasets.py
```

Il télécharge des fichiers épinglés à un commit et vérifie les empreintes SHA-256 publiées. Les fichiers et le manifeste restent locaux, ignorés par Git.

- `cic_ids2017/` : CSV quotidiens CIC-IDS2017, colonnes d’origine et colonne `Label`. Le lecteur combine les CSV et sélectionne seulement les variables requises.
- `unsw_nb15/` : train/test UNSW-NB15 du miroir public Mireu-Lab. La version nettoyée n'a pas les colonnes de ports ; le schéma commun remplit ces deux variables par zéro pour cette source uniquement. Le test fourni reste séparé de la validation utilisée pour le choix du modèle.
- `phishing.csv` : CSV encodé UTF-8 avec `text,label`; ajouter `language_group` pour l’analyse de biais.
- `phishing_language_groups.csv` : jeu de test autorisé avec `text,label,language_group`, annotation humaine standard/togolaise.

Sources de démonstration et licences déclarées par leurs cartes : UNSW-NB15 sur [Mireu-Lab](https://huggingface.co/datasets/Mireu-Lab/UNSW-NB15) (GPL-3.0 pour ce miroir) et corpus d’e-mails sur [zefang-liu](https://huggingface.co/datasets/zefang-liu/phishing-email-dataset) (LGPL-3.0 déclarée par cette carte). Les cartes identifient des copies de jeux publiés ailleurs : ces licences de miroir ne déterminent pas nécessairement les droits sur les données originales. Vérifiez les conditions d’origine, les citations, les usages commerciaux et la redistribution avant tout autre usage. CIC-IDS2017 est obtenu sur le [site officiel](https://www.unb.ca/cic/datasets/ids-2017.html), avec formulaire d’inscription ; le téléchargement n’est pas automatisé. Les scores de la démo ne valent que pour les partitions effectivement entraînées et sont détaillés dans [docs/demo_results.md](../../docs/demo_results.md).

Les exemples togolais ne doivent être collectés qu’avec consentement et revue humaine. Le gabarit `data/annotations/togolese_examples.template.csv` ne contient que les en-têtes ; aucune donnée locale authentique n’a été fournie. Copiez-le vers `data/annotations/togolese_examples.csv`, fichier privé ignoré par Git et Docker.
