from backend.app.repositories.history_repository import list_events


def get_history(limit: int = 50) -> list[dict]:
    return list_events(limit)