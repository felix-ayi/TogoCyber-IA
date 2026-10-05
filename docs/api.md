# API FastAPI v1

Base URL locale : `http://localhost:8000`. OpenAPI interactif : `/docs`.

## Santé

`GET /api/v1/health` renvoie la santé du serveur, la disponibilité des fichiers modèles (`models.network`, `models.phishing`) et l’état de configuration de l’assistant. `status=healthy` indique la disponibilité du serveur, pas la validité scientifique des modèles.

## Analyse réseau

`POST /api/v1/network/analyze`

```json
{
  "features": {
    "duration": 1.2,
    "src_bytes": 512,
    "dst_bytes": 128,
    "src_packets": 4,
    "dst_packets": 2,
    "src_port": 51515,
    "dst_port": 443,
    "protocol_number": 6,
    "flow_rate": 5
  }
}
```

Toutes les 9 clés sont obligatoires, numériques et finies ; les compteurs, durée, ports et débit ne peuvent pas être négatifs ; ports ≤ 65535 et protocole ≤ 255. Aucune clé supplémentaire n’est acceptée dans le service. Retour : classe bénigne/malveillante, probabilité, confiance, explication SHAP locale et identifiant d’historique (sans valeurs d’entrée stockées). HTTP 422 pour données invalides, 503 si modèle non entraîné.

## Analyse phishing

`POST /api/v1/phishing/analyze` avec `{"text":"..."}` (1–20 000 caractères). Retourne classe, probabilité phishing, niveau de confiance, termes LIME et identifiant historique. La prédiction utilise le message complet ; LIME est borné à 200 échantillons et aux 2 000 premiers caractères. `explanation_truncated` signale quand l’explication ne couvre qu’un extrait. Au plus deux analyses phishing simultanées sont admises par processus ; les demandes excédentaires reçoivent HTTP 429. HTTP 422 si vide/invalide, HTTP 503 si modèle absent.

## Assistant

`POST /api/v1/assistant/ask` avec `{"message":"..."}` ; longueur 1–8 000 et contenu non blanc. Nécessite `OPENAI_API_KEY`, sinon 503. Une erreur fournisseur ou réponse invalide n’est pas transformée en succès. Le contenu est envoyé au fournisseur, pas à SQLite.

## Historique

`GET /api/v1/history?limit=50` accepte 1–100 ; seuls métadonnées de résultats sont retournées.

## Sécurité d’exploitation

Prototype sans authentification ni autorisation par tenant : ne pas exposer publiquement sans reverse proxy TLS, authentification, limitation de débit, supervision et contrôles opérateur. La limite de concurrence est locale à chaque processus ; elle ne remplace pas une limitation de débit partagée entre processus ou instances. CORS configurable ; ne permet aucun scan réseau.