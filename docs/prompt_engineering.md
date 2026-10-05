# Assistant : prompt engineering et coût/latence

## Structure du prompt

1. Message système en français : rôle de prévention, ton simple, incertitude visible.
2. Défenses : conseils non offensifs adaptés au contexte togolais ; interdiction de demander OTP, mot de passe ou numéro Mobile Money.
3. Une question utilisateur (sans stockage local).
4. Réponse bornée en longueur, assortie d’un avertissement prototype.

Le service limite la température à 0,2 et la génération à 500 tokens pour limiter variations et durée. Le modèle par défaut configurable est `gpt-4o-mini`. Il n’y a pas d’exemples prétendument authentiques intégrés : few-shot à ajouter uniquement à partir d’exemples validés et autorisés. Le prompt n’est pas utilisé pour remplacer les classifieurs ML.

## Coût et latence

Chaque demande entraîne une requête HTTPS à `api.openai.com` avec timeout connect/read 5/30 secondes. Le tarif, la disponibilité et la latence réels dépendent du modèle, du compte et du fournisseur ; ils ne sont pas vérifiés par ce dépôt. Suivre les quotas et coûts dans la console du fournisseur. Sans clé, erreur explicite HTTP 503 ; erreur réseau/fournisseur n’est pas maquillée en réponse générée localement.

## Confidentialité

La question est transmise au fournisseur et n’est pas persistée localement. Informer l’utilisateur et ne pas soumettre de données confidentielles. Configurer la politique du fournisseur en fonction des obligations applicables.