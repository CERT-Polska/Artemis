#!/usr/bin/env python3
"""
Reusable SOCKS proxy prober using Python stdlib only (no external dependencies).
Supports SOCKS5 (RFC 1928) and SOCKS4.
"""

import socket
from typing import Optional


def probe_socks(host: str, port: int, timeout: float) -> Optional[int]:
    """
    Probe host:port to check if it accepts unauthenticated SOCKS connections.

    Returns:
        5 if SOCKS5 unauthenticated access confirmed
        4 if SOCKS4 unauthenticated access confirmed
        None if not a SOCKS proxy or connection failed
    """
    # SOCKS5: send greeting, expect \x05\x00 (no auth required)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(b"\x05\x01\x00")
            response = sock.recv(2)
            if len(response) == 2 and response == b"\x05\x00":
                return 5
    except Exception:
        pass

    # SOCKS4: CONNECT to 127.0.0.1:80, expect \x00\x5A (request granted)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(b"\x04\x01\x00\x50\x7f\x00\x00\x01\x00")
            response = sock.recv(8)
            if len(response) >= 2 and response[1] == 0x5A:
                return 4
    except Exception:
        pass

    return None
