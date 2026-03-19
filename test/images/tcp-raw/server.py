"""Minimal TCP server that speaks no known protocol.

Used in integration tests to create a port that:
- naabu detects as open
- fingerprintx cannot identify (returns empty output after retries)
- HTTP fallback also fails (response is not valid HTTP)

This exercises the full retry + fallback + skip path end-to-end.
"""

import socket
import threading


def handle(conn: socket.socket) -> None:
    try:
        conn.recv(4096)
        conn.sendall(b"XRAW PROTOCOL v1\n")
    except Exception:
        pass
    finally:
        conn.close()


def main() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 80))
    srv.listen(128)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
