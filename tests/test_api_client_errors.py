from frontend.services.api_client import _format_error_detail


def test_format_error_detail_handles_validation_lists() -> None:
    payload = {
        "detail": [
            {"loc": ["body", "email"], "msg": "String should have at least 3 characters"},
            {"loc": ["body", "password"], "msg": "String should have at least 1 character"},
        ]
    }

    assert _format_error_detail(payload) == (
        "String should have at least 3 characters (email); "
        "String should have at least 1 character (password)"
    )
