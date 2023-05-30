import functools
import urllib.parse
from socket import gethostbyname, getservbyname, getservbyport
from typing import Any, Dict, Optional

from artemis import http_requests


def get_target(task_result: Dict[str, Any]) -> str:
    """Returns a string representation of the target that has been scanned."""
    headers = task_result["headers"]
    payload = task_result["payload"]
    if "url" in payload:
        assert isinstance(payload["url"], str)
        return payload["url"]
    if "host" in payload and headers["service"] == "http":
        assert isinstance(payload["host"], str)
        return ("https" if payload["ssl"] else "http") + "://" + payload["host"] + ":" + str(payload["port"]) + "/"
    raise NotImplementedError(f"Unable to obtain viable target in {payload}")


def get_top_level_target_if_present(task_result: Dict[str, Any]) -> Optional[str]:
    """Returns the top level target - i.e. what was initially provided by the user as the target to scan.

    For example, the top level target may be example.com, but the actual vulnerability may be
    found on https://subdomain.example.com:443/.
    """
    payload_persistent = task_result["payload_persistent"]

    if "original_domain" in payload_persistent:
        assert isinstance(payload_persistent["original_domain"], str)
        return payload_persistent["original_domain"]
    elif "original_ip" in payload_persistent:
        assert isinstance(payload_persistent["original_ip"], str)
        return payload_persistent["original_ip"]
    else:
        return None


def get_top_level_target(task_result: Dict[str, Any]) -> str:
    target = get_top_level_target_if_present(task_result)
    if target:
        return target
    else:
        raise ValueError(f"No top level target found in {task_result}")


def get_scheme_from_url(url: str) -> str:
    return urllib.parse.urlparse(url).scheme


def get_host_from_url(url: str) -> str:
    host = urllib.parse.urlparse(url).hostname
    assert host is not None
    return host


def get_port_from_url(url: str) -> int:
    url_parsed = urllib.parse.urlparse(url)
    port = url_parsed.port

    if not port:
        return getservbyname(url_parsed.scheme)
    return port


@functools.lru_cache(maxsize=8192)
def cached_gethostbyname(host: str) -> str:
    """Please keep in mind that the requests will not be proxied
    and will leak information about what you are testing."""
    return gethostbyname(host)


def add_port_to_url(url: str) -> str:
    url_parsed = urllib.parse.urlparse(url)
    url_parsed_dict = url_parsed._asdict()
    if ":" not in url_parsed.netloc:
        if url_parsed.scheme == "http":
            port = 80
        elif url_parsed.scheme == "https":
            port = 443
        else:
            raise NotImplementedError()
        url_parsed_dict["netloc"] = url_parsed_dict["netloc"] + ":" + str(port)
    return urllib.parse.urlunparse(urllib.parse.ParseResult(**url_parsed_dict))


@functools.lru_cache(maxsize=8192)
def cached_get(url: str, **kwargs: Any) -> http_requests.HTTPResponse:
    """Cached HTTP GET.

    Please keep in mind that the requests will not be proxied
    and will leak information about what you are testing."""
    return http_requests.get(url, **kwargs)


def add_protocol_if_needed(data: str) -> str:
    """If data is in the form of host:port, adds a protocol - e.g. converts 127.0.0.1:3306
    to mysql://127.0.0.1:3306"""
    if "://" in data:
        return data
    elif ":" in data:
        host, port = data.split(":")
        port_int = int(port)
        return f"{_getservbyport(port_int)}://{host}:{port}"
    return data


def _getservbyport(port: int) -> str:
    try:
        return getservbyport(port)
    except OSError:
        if port == 3310:
            return "clamav"
        if port == 8009:
            return "ajp"
        raise OSError(f"Unable to get service associated with port {port}")
