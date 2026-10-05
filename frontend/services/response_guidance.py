"""Conservative, defensive next steps for model outputs."""

from typing import TypedDict


class ActionGuidance(TypedDict):
    title: str
    actions: list[str]
    caution: str


_GUIDANCE: dict[tuple[str, str], ActionGuidance] = {
    ("phishing", "phishing"): {
        "title": "Précautions recommandées",
        "actions": [
            "Ne cliquez pas sur les liens et n’ouvrez pas les pièces jointes de ce message.",
            "Ne communiquez aucun mot de passe, code OTP ou donnée bancaire en réponse.",
            "Vérifiez la demande en passant par le site ou le numéro officiel, saisi indépendamment du message.",
            "Signalez le message à votre opérateur ou à votre équipe informatique, puis supprimez-le.",
        ],
        "caution": "Le score est un signal automatisé, pas une preuve qu’un message est malveillant.",
    },
    ("phishing", "legitimate"): {
        "title": "Vérifications utiles",
        "actions": [
            "Aucun signal fort n’a été relevé par ce modèle ; cela ne garantit pas que le message est sûr.",
            "En cas de demande urgente, financière ou inhabituelle, confirmez-la via un canal officiel indépendant.",
            "Ne partagez pas de code OTP ni de mot de passe depuis un lien reçu par message.",
        ],
        "caution": "Un résultat sans alerte ne garantit pas que le message est sûr. Le modèle a été évalué sur des courriels anglais de démonstration ; ses résultats ne valident pas le français ni les SMS togolais.",
    },
    ("network", "malicious"): {
        "title": "Vérifications recommandées",
        "actions": [
            "Traitez ce résultat comme une alerte à vérifier, pas comme une confirmation d’incident.",
            "Transmettez les détails du flux à l’administrateur ou à l’équipe de sécurité autorisée.",
            "Suivez la procédure de réponse aux incidents de votre organisation avant toute action sur l’équipement.",
        ],
        "caution": "Cette prédiction porte sur neuf caractéristiques résumées ; elle ne remplace pas l’analyse des journaux et du contexte.",
    },
    ("network", "benign"): {
        "title": "Suite de vérification",
        "actions": [
            "Aucun signal fort n’a été relevé dans les caractéristiques soumises ; cela ne prouve pas que le réseau est sain.",
            "Continuez la surveillance habituelle et confrontez ce résultat aux journaux et alertes disponibles.",
            "Faites vérifier tout comportement inhabituel par une personne autorisée.",
        ],
        "caution": "Le score dépend des données et du modèle de démonstration ; il ne garantit pas l’absence d’attaque.",
    },
}


def get_action_guidance(module: str, prediction: str) -> ActionGuidance:
    try:
        guidance = _GUIDANCE[(module, prediction)]
    except KeyError as exc:
        raise ValueError(f"unsupported analysis result: {module}/{prediction}") from exc
    return {
        "title": guidance["title"],
        "actions": list(guidance["actions"]),
        "caution": guidance["caution"],
    }
