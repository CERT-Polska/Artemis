import copy
import functools
import urllib.parse
from socket import getservbyname, getservbyport
from typing import Any, Dict

from karton.core import Task

from artemis import http_requests, task_utils, utils
from artemis.config import Config
from artemis.domains import is_subdomain


def get_target_url(task_result: Dict[str, Any]) -> str:
    """Returns a string representation of the target that has been scanned."""
    return task_utils.get_target_url(Task(headers=task_result["headers"], payload=task_result["payload"]))


REPORTING_SEPARATE_INSTITUTIONS = copy.copy(Config.Reporting.REPORTING_SEPARATE_INSTITUTIONS)

if Config.Reporting.REPORTING_SEPARATE_INSTITUTIONS_FILE:
    for line in open(Config.Reporting.REPORTING_SEPARATE_INSTITUTIONS_FILE):
        line = line.strip()
        if line:
            REPORTING_SEPARATE_INSTITUTIONS.append(line)

REPORTING_SEPARATE_INSTITUTIONS_FROZENSET = frozenset(REPORTING_SEPARATE_INSTITUTIONS)

logger = utils.build_logger(__name__)

if len(REPORTING_SEPARATE_INSTITUTIONS_FROZENSET):
    logger.info(
        "Loaded %s domains that will be treated as ones where separate reports will be created",
        len(REPORTING_SEPARATE_INSTITUTIONS_FROZENSET),
    )


def get_top_level_target(task_result: Dict[str, Any]) -> str:
    """Returns the top level target - i.e. what was initially provided by the user as the target to scan.

    For example, the top level target may be example.com, but the actual vulnerability may be
    found on https://subdomain.example.com:443/.
    """

    payload_persistent = task_result["payload_persistent"]

    # Sometimes subdomain.example.com is managed by an institution separate from example.com. In such
    # cases, we return a separate top level target, so that all reports in subdomain.example.com will
    # get grouped in a separate e-mail.
    if "last_domain" in task_result["payload"]:
        last_domain = task_result["payload"]["last_domain"]

        last_domain_parts = last_domain.split(".")
        for i, _ in enumerate(last_domain_parts):
            item = ".".join(last_domain_parts[i:])
            if item in REPORTING_SEPARATE_INSTITUTIONS_FROZENSET:
                assert "original_domain" in payload_persistent
                if is_subdomain(item, payload_persistent["original_domain"]):  # not exceeded the tree to far
                    logger.info(
                        "Not sending the report to %s, but to %s, as it's marked as a separate institution",
                        payload_persistent["original_domain"],
                        item,
                    )
                    return item

    if "original_domain" in payload_persistent:
        assert isinstance(payload_persistent["original_domain"], str)
        return payload_persistent["original_domain"]
    elif "original_ip" in payload_persistent:
        assert isinstance(payload_persistent["original_ip"], str)
        return payload_persistent["original_ip"]
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


def add_port_to_url(url: str) -> str:
    url_parsed = urllib.parse.urlparse(url)
    url_parsed_dict = url_parsed._asdict()
    if ":" not in url_parsed.netloc:
        port = getservbyname(url_parsed.scheme)
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
        try:
            service_name = getservbyport(port_int)
        except OSError:
            service_name = "unknown"
        return f"{service_name}://{host}:{port}"
    return data
