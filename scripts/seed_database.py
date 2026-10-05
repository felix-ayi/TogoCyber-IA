"""Initialize SQLite schema without fabricating demonstration history."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.app.repositories.history_repository import initialize_database


if __name__ == "__main__":
    initialize_database()
    print("SQLite schema initialized; no synthetic history was inserted.")