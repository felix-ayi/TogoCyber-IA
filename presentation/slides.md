# TogoCyber AI — plan de présentation

## 1. Problème et public
Menaces de phishing/smishing et de flux réseau ; citoyens, PME et opérateurs au Togo. Prototype de recherche, pas un service certifié.

## 2. Solution
Dashboard Streamlit en français, API FastAPI intégrable, classifieurs réseau et texte, assistant de prévention optionnel.

## 3. Méthode scientifique
CIC-IDS2017 pour entraîner le réseau, UNSW-NB15 pour un test croisé exploratoire ; corpus phishing public et exemples locaux consentis ; splits 60/20/20.

## 4. Modèles et mesure
Random Forest vs XGBoost ; TF-IDF + régression logistique vs Naive Bayes ; accuracy, precision, recall, F1, PR-AUC et G-mean. **Insérer uniquement les métriques réellement produites à partir des CSV autorisés.**

## 5. Explicabilité et contextualisation
SHAP pour les flux, LIME pour les textes ; jeu togolais anonymisé et annoté humainement à acquérir ; analyse de biais français standard/familier.

## 6. Démonstration produit
API versionnée, historique sans contenu brut et rétention courte, pages légales, UX mobile et erreurs explicites.

## 7. Limites et prochaines étapes
Métriques non vérifiées avant données ; faux positifs/faux négatifs ; décalage de domaine ; authentification, supervision, licences, robustesse et revue juridique avant production.
