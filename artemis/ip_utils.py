import ipaddress
from typing import List, Optional


def is_ip_address(host: str) -> bool:
    try:
        # if this doesn't throw then we have an IP address
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def to_ip_range(data: str) -> Optional[List[str]]:
    if "-" in data:
        start_ip_str, end_ip_str = data.split("-", 1)
        start_ip_str = start_ip_str.strip()
        end_ip_str = end_ip_str.strip()

        if not is_ip_address(start_ip_str) or not is_ip_address(end_ip_str):
            return None

        start_ip = ipaddress.ip_address(start_ip_str)
        end_ip = ipaddress.ip_address(end_ip_str)

        if ":" in data:
            return None  # IPv6 ranges are not supported

        cls = ipaddress.IPv4Address
        return [str(cls(i)) for i in range(int(start_ip), int(end_ip) + 1)]
    if "/" in data:
        ip, mask = data.split("/", 1)
        ip = ip.strip()
        mask = mask.strip()

        if not is_ip_address(ip) or not mask.isdigit() or ":" in ip:
            return None

        return list(map(str, ipaddress.ip_network(data.strip(), strict=False)))
    return None
