from frontend.views.authentication import build_bootstrap_admin_hint


def test_build_bootstrap_admin_hint_formats_email() -> None:
    assert build_bootstrap_admin_hint("root@example.org") == (
        "Compte administrateur prêt à l’emploi : root@example.org"
    )
    assert build_bootstrap_admin_hint("") == ""
