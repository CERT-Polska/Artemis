import functools
import ipaddress

import requests


def get_cloudflare_ips() -> list[str]:
    response = requests.get(
        "https://api.cloudflare.com/client/v4/ips",
        timeout=30,
    )
    response.raise_for_status()

    payload = response.json()
    if not payload.get("success"):
        raise RuntimeError(f"Cloudflare API error: {payload['errors']}")

    result = payload["result"]
    return list(result["ipv4_cidrs"] + result["ipv6_cidrs"])


@functools.lru_cache(maxsize=10)
def get_cdn_ip_ranges() -> list[str]:
    return get_cloudflare_ips()


def is_cdn_ip(ip: str) -> bool:
    for network in get_cdn_ip_ranges():
        if ipaddress.ip_address(ip) in ipaddress.ip_network(network):
            return True

    return False
