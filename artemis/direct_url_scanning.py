import socket
import urllib.parse
from typing import Dict, NamedTuple, Optional, Tuple

from artemis.binds import Service


class ParsedURL(NamedTuple):
    service: Service
    host: str
    port: int
    ssl: bool


# Maps a URL scheme to the service it implies and whether it uses SSL/TLS. The keys
# are exactly the schemes accepted as direct scan targets.
SCHEME_TO_SERVICE: Dict[str, Tuple[Service, bool]] = {
    "http": (Service.HTTP, False),
    "https": (Service.HTTP, True),
    "ftp": (Service.FTP, False),
    "ftps": (Service.FTP, True),
    "ssh": (Service.SSH, False),
    "smtp": (Service.SMTP, False),
    "smtps": (Service.SMTP, True),
    "imap": (Service.IMAP, False),
    "imaps": (Service.IMAP, True),
    "mysql": (Service.MYSQL, False),
    "postgresql": (Service.POSTGRESQL, False),
    "postgres": (Service.POSTGRESQL, False),
}


def parse_url(data: str) -> Optional[ParsedURL]:
    """
    Parses a root URL (`scheme://host[:port][/]`) into the service it implies.

    Returns `None` for anything that isn't a supported root URL: an input without
    a scheme, an unmapped scheme, a missing host, userinfo, or a non-root path,
    parameters, query or fragment. `urlparse` lowercases the scheme and host and
    unwraps bracketed IPv6 hosts for us; `hostname`/`port` raise `ValueError`
    on a malformed host or out-of-range port, which we treat as unsupported.
    """
    if "://" not in data:
        return None

    try:
        parsed = urllib.parse.urlparse(data)
    except ValueError:
        return None

    mapping = SCHEME_TO_SERVICE.get(parsed.scheme)
    if mapping is None:
        return None

    # Userinfo (e.g. user:pass@host) points at credentials, not a target.
    if parsed.username is not None or parsed.password is not None:
        return None

    # Only a root URL is accepted - service modules crawl from the root themselves,
    # so a path, parameters, query or fragment would be ambiguous.
    if parsed.path not in ("", "/") or parsed.params or parsed.query or parsed.fragment:
        return None

    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    if not host:
        return None

    service, ssl = mapping
    if port is None:
        # No explicit port - fall back to the scheme's default from the system
        # services database, the same way the reporting code resolves it.
        try:
            port = socket.getservbyname(parsed.scheme)
        except OSError:
            return None

    return ParsedURL(service=service, host=host, port=port, ssl=ssl)


def is_scannable_url(data: str) -> bool:
    """Whether `data` is a root URL that is accepted as a direct scan target."""
    return parse_url(data) is not None
