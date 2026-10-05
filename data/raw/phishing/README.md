# Corpus phishing / smishing

Pour une démonstration, `python scripts\download_demo_datasets.py` télécharge le corpus d’e-mails anglais épinglé depuis [zefang-liu/phishing-email-dataset](https://huggingface.co/datasets/zefang-liu/phishing-email-dataset) (carte indiquant LGPL-3.0) et vérifie son SHA-256. La version source `Phishing_Email.csv` est acceptée directement. Vérifiez les conditions des sources originales avant tout usage autre que la démo : la licence d’un miroir n’établit pas à elle seule les droits sur son contenu.

Un corpus personnalisé peut être placé dans `data/raw/phishing.csv`, avec les colonnes :

```text
text,label
...
```

Les labels positifs acceptés incluent `1`, `phishing`, `phish`, `phishing email`, `smishing`, `malicious` et `spam`; les négatifs incluent `0`, `legitimate`, `benign`, `ham`, `safe`, `safe email` et `normal`. Un message `spam` n’est pas nécessairement une tentative de phishing : n’utilisez ce label positif que si les consignes du corpus le définissent ainsi ou après annotation manuelle. Le corpus public téléchargé est en anglais ; il ne valide ni les SMS, ni le français togolais.

Pour l’analyse de biais, un jeu de test distinct `data/raw/phishing_language_groups.csv` doit aussi contenir la colonne annotée `language_group` avec `standard_french` ou `togolese_french`.
