import socket
import urllib.parse
from typing import Tuple

from artemis.config import Config

# A normal form of a single vulnerability report. This should be generated in such a way that
# vulnerabilities that should be deduplicated (e.g. exposed http://example.com/wp-config.php.bak
# and https://www.example.com/wp-config.php.bak) have the same normal form.
NormalForm = Tuple[Tuple[str, str], ...]


def get_url_normal_form(url: str) -> str:
    """
    Normalizes a URL.

    If it's on a standard port we set the port to 0 and set the schema to http_or_https so that
    http://service.com:80/ and https://service.com:443/ will get the same normal form.

    We also normalize the domain by stripping www.
    """

    assert "://" in url

    url_parsed = urllib.parse.urlparse(url)
    url_parsed_dict = url_parsed._asdict()
    assert url_parsed.hostname

    port = url_parsed.port

    if not port:
        port = socket.getservbyname(url_parsed.scheme)

    hostname = get_domain_normal_form(url_parsed.hostname)

    if url_parsed.scheme in ["http", "https"] and port in Config.Reporting.REPORTING_DEDUPLICATION_COMMON_HTTP_PORTS:
        url_parsed_dict["scheme"] = "http_or_https"
        url_parsed_dict["netloc"] = hostname + ":0"
    else:
        url_parsed_dict["netloc"] = hostname + ":" + str(port)

    return urllib.parse.urlunparse(urllib.parse.ParseResult(**url_parsed_dict))


def get_domain_normal_form(domain: str) -> str:
    """
    Normalizes a domain - if it starts with www, strips it.
    """
    assert ":" not in domain, f"Provided string, {domain}, doesn't look like a domain"

    return domain.removeprefix("www.")


def get_url_score(url: str) -> int:
    """
    Returns a URL score - for multiple similar problems on different URLs with the same
    normal form, the one with highest score will be reported.

    https:// is more canonical than http://, domain that doesn't start with www is more canonical than
    one that starts with www.
    """
    assert "://" in url

    url_parsed = urllib.parse.urlparse(url)
    assert url_parsed.hostname
    score = 0
    if url_parsed.scheme == "https":
        score += 2
    if url_parsed.hostname.startswith("www."):
        score -= 1
    return score


def get_domain_score(domain: str) -> int:
    """
    Returns a domain score - for multiple similar problems on different domains with the same
    normal form, the one with highest score will be reported.

    We treat domains without "www" as more canonical, therefore they should get a higher score.
    """
    assert ":" not in domain

    if domain.startswith("www."):
        return 0
    else:
        return 1
