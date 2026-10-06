from backend.app.repositories.history_repository import list_events


def get_history(limit: int = 50, user_id: int | None = None, offset: int = 0) -> list[dict]:
    return list_events(limit, user_id=user_id, offset=offset)