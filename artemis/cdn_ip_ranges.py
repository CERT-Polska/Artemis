import functools
import ipaddress
import re
from typing import Any

import requests

from artemis import utils

logger = utils.build_logger(__name__)


def get_azure_front_door_ips() -> list[Any]:
    response = requests.get(
        "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519",
        timeout=30,
    )
    response.raise_for_status()

    match = re.search(
        r'https://download\.microsoft\.com/[^"\']+/ServiceTags_Public_[^"\']+\.json',
        response.text,
        re.IGNORECASE,
    )
    if not match:
        raise RuntimeError("Could not find current Azure ServiceTags JSON URL")

    json_url = match.group(0)

    response = requests.get(json_url, timeout=30)
    response.raise_for_status()

    payload = response.json()

    for item in payload["values"]:
        if item["name"] == "AzureFrontDoor.Frontend":
            return [ipaddress.ip_network(prefix) for prefix in item["properties"]["addressPrefixes"]]

    raise RuntimeError("AzureFrontDoor.Frontend not found")


def get_cloudflare_ips() -> list[Any]:
    response = requests.get(
        "https://api.cloudflare.com/client/v4/ips",
        timeout=30,
    )
    response.raise_for_status()

    payload = response.json()
    if not payload.get("success"):
        raise RuntimeError("Cloudflare API error: {payload['errors']}")

    result = payload["result"]
    return [ipaddress.ip_network(item) for item in result["ipv4_cidrs"] + result["ipv6_cidrs"]]


def get_cloudfront_ips() -> list[Any]:
    response = requests.get(
        "https://ip-ranges.amazonaws.com/ip-ranges.json",
        timeout=30,
    )
    response.raise_for_status()

    payload = response.json()

    networks = []

    for item in payload["prefixes"]:
        if item["region"] == "GLOBAL" and item["service"] == "CLOUDFRONT":
            networks.append(ipaddress.ip_network(item["ip_prefix"]))

    for item in payload["ipv6_prefixes"]:
        if item["region"] == "GLOBAL" and item["service"] == "CLOUDFRONT":
            networks.append(ipaddress.ip_network(item["ipv6_prefix"]))

    return networks


def get_fastly_ips() -> list[Any]:
    response = requests.get(
        "https://api.fastly.com/public-ip-list",
        timeout=30,
    )
    response.raise_for_status()

    payload = response.json()

    return [ipaddress.ip_network(item) for item in payload["addresses"] + payload["ipv6_addresses"]]


def get_bunnycdn_ips() -> list[Any]:
    ips: list[Any] = []

    for url in (
        "https://api.bunny.net/system/edgeserverlist/plain",
        "https://api.bunny.net/system/edgeserverlist/ipv6/plain",
    ):
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        ips.extend(ipaddress.ip_network(line.strip()) for line in response.text.splitlines() if line.strip())

    return ips


@functools.lru_cache(maxsize=1)
def get_cdn_ip_ranges() -> set[Any]:
    result = set()
    for get_ranges in [
        get_azure_front_door_ips,
        get_cloudflare_ips,
        get_cloudfront_ips,
        get_fastly_ips,
        get_bunnycdn_ips,
    ]:
        try:
            for network in get_ranges():
                result.add(network)
        except Exception:
            logger.exception("Unable to obtain networks for %s", get_ranges.__name__)
    return result


def is_cdn_ip(ip: str) -> bool:
    address = ipaddress.ip_address(ip)

    return any(address in network for network in get_cdn_ip_ranges())
