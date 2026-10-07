import socket

from scripts.dev_launcher import choose_free_port


def test_choose_free_port_returns_available_port() -> None:
    port = choose_free_port(8000)
    assert port >= 1
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", port))
