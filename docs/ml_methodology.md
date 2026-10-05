# Méthodologie ML

## Réseau

- Source attendue : CIC-IDS2017 ; label `Label`, `BENIGN` devient 0 et autre libellé non vide devient 1.
- Baselines : Random Forest avec pondération `balanced` et XGBoost avec poids positif calculé uniquement sur le train.
- Variables communes : `duration`, `src_bytes`, `dst_bytes`, `src_packets`, `dst_packets`, `src_port`, `dst_port`, `protocol_number`, `flow_rate`.
- Prétraitement : conversions numériques, infinis en valeurs manquantes, imputation médiane apprise dans pipeline.
- Le chargeur prend un CSV ou un dossier de CSV quotidiens. L’entraînement utilise par défaut un échantillon aléatoire stratifié reproductible de 250 000 flux (plafond configurable) pour rester utilisable sur une machine de démonstration ; fixer `max_rows=None` pour entraîner sur tout le corpus. Le nombre de lignes réellement utilisées apparaît dans la sortie.
- Comparaison stratifiée 60/20/20, seed 42 ; seuil 0,5. Choix sur F1 validation, métriques accuracy, precision, recall, F1, average precision, ROC-AUC calculées sur test. Modèle choisi ensuite réentraîné sur train+validation ; second rapport test est indiqué séparément.

## Phishing/smishing

- CSV avec colonnes `text,label` ; labels de phishing et légitimes explicitement reconnus.
- Un corpus optionnel `phishing_with_togolese.csv` peut être préparé à partir de 50–100 exemples locaux sourcés, consentis et manuellement étiquetés ; aucun exemple n’est livré.
- Deux pipelines : TF-IDF de mots et bigrammes + régression logistique pondérée, et TF-IDF + Naive Bayes multinomial.
- Le vocabulaire TF-IDF est appris dans le pipeline sur train uniquement ; split stratifié, seed, seuil et mesures identiques au module réseau.

## Explicabilité

SHAP `TreeExplainer` attribue à un flux les contributions des variables pour le modèle en arbre. LIME perturbe localement un texte et explique les termes liés à la classe phishing. Ces contributions dépendent du modèle et de l’exemple ; elles ne démontrent pas de causalité ni la vérité d’une alerte.

## Généralisation et biais

Le modèle CIC est appliqué à UNSW-NB15 sans réentraînement ; les noms et distributions des colonnes diffèrent, donc la projection commune est expérimentale, et les scores ne sont pas strictement comparables. Pour le biais, ajouter une annotation manuelle `language_group` (`standard_french` ou `togolese_french`) à un jeu de test représentatif et équilibré par classe. Sans données annotées suffisantes, aucun constat de biais n’est possible.

## Résultats

**RÉSULTAT NON VÉRIFIÉ — à exécuter avec les vraies données.** Les CSV requis ne sont pas inclus ; le code et les sorties métriques sont fournis, mais aucune performance n’est affirmée.