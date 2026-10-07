import streamlit as st


def render() -> None:
    st.subheader("Guide utilisateur")
    st.caption("Démarrage rapide pour utiliser la plateforme de manière sûre et cohérente.")

    st.markdown(
        """
        <div class="tc-knowledge-shell">
          <div class="tc-knowledge-card">
            <span class="tc-soc-summary-kicker">DÉMARRAGE RAPIDE</span>
            <h3>Procédure de mise en route</h3>
          </div>
          <div class="tc-knowledge-card">
            <span class="tc-soc-summary-kicker">SÉCURITÉ</span>
            <h3>Utilisez des données de test</h3>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    guide_steps = [
        ("1. Inscription", "Créez un compte depuis l’écran d’accès. Le mot de passe doit contenir au moins 12 caractères. Les comptes publics sont limités au rôle Utilisateur."),
        ("2. Compte bootstrap de démonstration", "Si le projet est démarré localement avec BOOTSTRAP_ADMIN_EMAIL et BOOTSTRAP_ADMIN_PASSWORD, utilisez le bouton de préremplissage sur l’écran de connexion pour ouvrir immédiatement le compte administrateur de démo."),
        ("3. Connexion", "Saisissez votre e-mail et votre mot de passe. En cas d’échec répété, l’API protège la plateforme contre les attaques de force brute."),
        ("4. Réinitialisation de mot de passe", "Depuis l’écran de connexion, cliquez sur Mot de passe oublié. En mode demo sans SMTP, le token de réinitialisation est affiché localement pour permettre la validation sans serveur mail."),
        ("5. Tableau de bord", "Le tableau de bord présente les indicateurs de sécurité, l’historique et les alertes disponibles selon votre rôle."),
        ("6. Analyse phishing", "Collez un message ou un SMS suspect pour lancer une analyse. Vérifiez toujours le contexte avant de prendre une décision."),
        ("7. Analyse URL", "Testez des liens suspects. L’outil s’appuie sur des heuristiques locales, sans réputation externe en temps réel."),
        ("8. IOC", "Consultez les indicateurs observés et leur niveau de gravité. Cette section cible les analystes et les administrateurs."),
        ("9. Réseau", "Analysez les flux réseau à partir de caractéristiques compatibles avec le démonstrateur local. Les données doivent être pertinentes et autorisées."),
        ("10. Alertes et incidents", "Suivez les alertes, leur statut et les incidents associés pour organiser l’investigation."),
        ("11. Dashboard SOC", "Visualisez les performances, les alertes et les éléments de vigilance selon les droits d’accès attribués."),
        ("12. Assistant IA", "Posez des questions sur la situation ou la procédure, si l’assistant est activé dans la configuration locale."),
        ("13. Profil", "Accédez à votre profil pour vérifier vos informations, votre rôle et le statut du compte."),
        ("14. Changement de mot de passe", "Depuis Mon profil, modifiez votre mot de passe en fournissant l’ancien mot de passe puis le nouveau."),
        ("15. Déconnexion", "Utilisez le bouton Se déconnecter situé en bas de la navigation pour fermer la session."),
    ]

    for title, text in guide_steps:
        with st.expander(title, expanded=False):
            st.write(text)

    st.info("Astuce : les outils de démonstration doivent être utilisés avec des données de test et non avec des informations sensibles ou confidentielles.")
