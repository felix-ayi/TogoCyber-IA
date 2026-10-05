# Résultats mesurés de la démonstration

**Exécution locale réelle, scores non simulés.** Ces mesures sont celles des exécutions des scripts ci-dessous, pas une certification, une réplication indépendante, ni une validation sur des menaces togolaises. Les téléchargements utilisés sont consignés avec leurs URL épinglées et empreintes SHA-256 dans `data/raw/demo_sources.json` (fichier local ignoré par Git).

## Réseau

- Source : train/test UNSW-NB15 fourni par le miroir public Mireu-Lab, version épinglée ; les CSV ont passé la vérification SHA-256.
- Modèle sélectionné : XGBoost, choisi sur la partition validation (F1 = **0,9404**).
- Test fourni séparément par la source : **175 341** flux.
- Après réentraînement sur tout le fichier train, métriques mesurées sur le test : accuracy **0,9023**, précision **0,9811**, rappel **0,8732**, F1 **0,9240**, average precision **0,9923**, ROC-AUC **0,9840**, moyenne géométrique **0,9176**.
- Deux modèles comparés : Random Forest (F1 test **0,9247**) et XGBoost (F1 test du modèle de validation **0,9235** ; après réentraînement sur l’intégralité du train, **0,9240**).
- Le miroir nettoyé ne comporte pas `sport` ni `dsport` : ces variables valent zéro pendant apprentissage, test et inférence. Ce résultat n’est pas une évaluation CIC-IDS2017 ni CIC→UNSW.

Commande exécutée :

```powershell
python scripts\train_network.py --dataset unsw --data data\raw\unsw_nb15\train.csv --test-data data\raw\unsw_nb15\test.csv
```

## Courriels de phishing

- Source : copie anglaise du corpus Phishing Email hébergée par zefang-liu ; empreinte SHA-256 vérifiée. LGPL-3.0 est déclarée par le miroir ; vérifier les droits du jeu original avant réutilisation ou redistribution.
- Après normalisation : **18 631** courriels (11 322 légitimes, 7 309 phishing). Partition de test : **3 727** exemples.
- Modèle sélectionné : régression logistique TF-IDF, sélectionnée sur la validation (F1 = **0,9594**).
- Après réentraînement sur train + validation, test mesuré : accuracy **0,9708**, précision **0,9419**, rappel **0,9863**, F1 **0,9636**, average precision **0,9923**, ROC-AUC **0,9955**, moyenne géométrique **0,9734**.
- Deux modèles comparés : régression logistique et Naive Bayes multinomial.
- Il s’agit d’e-mails anglais. Aucune conclusion n’est permise sur les SMS, le français, les langues togolaises ou les arnaques Mobile Money.

Commande exécutée :

```powershell
python scripts\train_phishing.py --data data\raw\phishing\Phishing_Email.csv
```

## Portée et reproduction

Ces scores reflètent uniquement les partitions aléatoires fixées par `seed=42` dans les données décrites ci-dessus. Ils ne remplacent ni des données autorisées, représentatives et annotées localement, ni l’évaluation académique demandée dans le cahier des charges. Les explications SHAP (réseau) et LIME (texte) ont aussi été exécutées sur des exemples réels et ont retourné respectivement 5 et 4 contributions dans le smoke test. Elles sont locales et non causales.

Le registre `models/metadata/model_registry.json` conserve le modèle retenu, son jeu d’entraînement déclaré et ses métriques. Les artefacts, CSV et registre de la machine de démonstration ne sont pas inclus dans Git.

Le dashboard lit les métriques et le nombre d’exemples de test du registre via `/api/v1/health`. Il affiche le F1 et le ROC-AUC comme mesures de ces seuls jeux de démonstration, en rappelant leur périmètre ; les indicateurs d’historique sur l’accueil restent séparés des scores de test.
