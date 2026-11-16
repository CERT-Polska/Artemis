import contextlib
import ipaddress
import os
import socket
import threading
from typing import Any, Iterator

from artemis.config import Config


class SSRFDetected(Exception):
    pass


_BAD_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "::/128",
        "::1/128",
        "2001:0::/32",
        "2002::/32",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
    + tuple(Config.SSRF.SSRF_ADDITIONAL_BLOCKED_NETWORKS)
    + (tuple([]) if "RUNNING_TESTS" in os.environ else ("224.0.0.0/3",))  # this is the net used in tests
)


def ip_bad(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return any(ip in net for net in _BAD_NETS)
    except ValueError:
        return True


_fence = threading.local()
_getaddrinfo = socket.getaddrinfo


def _fenced_getaddrinfo(host: str, port: int, family: int = 0, type: int = 0, proto: int = 0, flags: int = 0) -> Any:
    if getattr(_fence, "on", False) and isinstance(host, str):
        infos = _getaddrinfo(host, port, family, type, proto, flags)
        if not infos or any(ip_bad(i[4][0]) for i in infos):  # type: ignore
            raise SSRFDetected()
        return infos
    return _getaddrinfo(host, port, family, type, proto, flags)


socket.getaddrinfo = _fenced_getaddrinfo  # type: ignore


@contextlib.contextmanager
def ssrf_fence() -> Iterator[None]:
    _fence.on = True
    try:
        yield
    finally:
        _fence.on = False
