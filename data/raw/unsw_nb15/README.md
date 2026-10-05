# UNSW-NB15

Pour la démonstration : `python scripts\download_demo_datasets.py` récupère les CSV train/test épinglés du miroir [Mireu-Lab](https://huggingface.co/datasets/Mireu-Lab/UNSW-NB15), et vérifie leurs empreintes. Cette copie est marquée GPL-3.0 par sa carte ; vérifiez les droits de l’UNSW-NB15 original, sa citation et les restrictions applicables avant usage autre que la démonstration.

Le modèle réseau se forme sur `train.csv` et utilise `test.csv` comme test indépendant ; lancer `python scripts\train_network.py --dataset unsw --data data\raw\unsw_nb15\train.csv --test-data data\raw\unsw_nb15\test.csv`. Le miroir nettoyé n'a pas `sport`/`dsport` ; elles valent zéro pour cette version. Des fichiers UNSW enrichis de ces colonnes peuvent être chargés sans ce placeholder. Les données sont exclues de Git et du build Docker. Ce parcours n'est pas un test CIC→UNSW.

Notebook d’évaluation croisée, depuis la racine du dépôt : `notebooks/06_generalization_analysis.ipynb`. Une projection commune de variables ne supprime pas le décalage de domaine CIC→UNSW.
