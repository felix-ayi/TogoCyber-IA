from backend.app.schemas.demo import DemoScenario, DemoStep


def build_demo_scenario() -> DemoScenario:
    return DemoScenario(
        incident_title="Tentative de compromission de compte et accès à un serveur critique",
        risk_score=92,
        severity="CRITICAL",
        asset="SERVER-001",
        facts=[
            "Un employé de TOGO BUSINESS SARL a reçu un e-mail de phishing simulé.",
            "Le message contenait une URL suspecte et un domaine non reconnu.",
            "La corrélation a associé plusieurs signaux : échecs de connexion, IP suspecte et accès serveur critique.",
            "Le risque global est évalué comme critique et correspond à la technique MITRE T1566.",
        ],
        recommendations=[
            "Isoler l’utilisateur concerné et révoquer la session active.",
            "Réinitialiser ses identifiants et vérifier les accès récents.",
            "Rechercher le domaine malveillant sur les autres postes de travail.",
            "Bloquer l’indicateur après validation humaine et documenter l’incident.",
        ],
        steps=[
            DemoStep(order=1, name="EVENT", description="E-mail de phishing reçu sur la messagerie de l’employé."),
            DemoStep(order=2, name="DETECTION", description="URL suspecte, domaine inhabituel et IOC associé détectés."),
            DemoStep(order=3, name="ENRICHMENT", description="Threat Intel confirme le domaine et l’IP comme malveillants."),
            DemoStep(order=4, name="CORRELATION", description="Plusieurs signaux sont liés à un incident probable unique."),
            DemoStep(order=5, name="RISK", description="Risk score calculé à 92/100, sévérité critique."),
            DemoStep(order=6, name="MITRE", description="Initial Access — T1566 Phishing."),
            DemoStep(order=7, name="INCIDENT", description="Incident critique créé avec timeline et recommandations."),
            DemoStep(order=8, name="RECOMMENDATION", description="Actions de réponse proposées à l’analyste pour validation humaine."),
        ],
    )
