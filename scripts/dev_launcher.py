from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def choose_free_port(preferred_port: int = 8000, max_attempts: int = 50) -> int:
    """Return the first free port starting from preferred_port."""
    for offset in range(max_attempts):
        candidate = preferred_port + offset
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", candidate))
            except OSError:
                continue
            return candidate
    raise RuntimeError(f"No free port available in range {preferred_port}-{preferred_port + max_attempts - 1}.")


def _python_executable() -> str:
    return sys.executable or "python"


def main() -> None:
    backend_port = choose_free_port(8000)
    frontend_port = choose_free_port(8501)
    backend_cmd = [
        _python_executable(),
        "-m",
        "uvicorn",
        "backend.app.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(backend_port),
    ]
    frontend_env = os.environ.copy()
    frontend_env["TOGOCYBER_API_URL"] = f"http://127.0.0.1:{backend_port}"
    frontend_cmd = [
        _python_executable(),
        "-m",
        "streamlit",
        "run",
        "frontend/app.py",
        "--server.address",
        "127.0.0.1",
        "--server.port",
        str(frontend_port),
    ]

    print(f"[TogoCyber] API: http://127.0.0.1:{backend_port}")
    print(f"[TogoCyber] UI: http://127.0.0.1:{frontend_port}")
    print("[TogoCyber] Starting backend and frontend...\n")

    backend_process = subprocess.Popen(backend_cmd, cwd=str(REPO_ROOT))
    frontend_process = subprocess.Popen(frontend_cmd, cwd=str(REPO_ROOT), env=frontend_env)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[TogoCyber] Stopping backend and frontend...")
        backend_process.terminate()
        frontend_process.terminate()
        for process in (backend_process, frontend_process):
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        print("[TogoCyber] Stopped.")


if __name__ == "__main__":
    main()
