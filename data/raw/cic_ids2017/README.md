# CIC-IDS2017

Téléchargez le jeu CSV via la page officielle : https://www.unb.ca/cic/datasets/ids-2017.html. Cette page exige un formulaire d’inscription. Téléchargez/extraire les fichiers par les voies officielles ; ne contournez pas cette inscription et vérifiez les conditions d’utilisation et la citation académique avant emploi.

Déposez les CSV quotidiens dans ce dossier (en conservant les colonnes originales CICFlowMeter et `Label`). Ne déposez pas les fichiers PCAP dans le dépôt. Les CSV locaux sont exclus de Git et du build Docker.

Depuis la racine du projet :

```powershell
python scripts\train_network.py --data data\raw\cic_ids2017
```

L’EDA et l’entraînement lisent le dossier entier ; l’entraînement prélève par défaut au plus 250 000 lignes au hasard de façon stratifiée et reproductible. `--max-rows 0` désactive le plafond. Aucun score n’est disponible avant l’exécution réelle.
