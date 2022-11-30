from typing import Any, Dict, List, Set

import requests

DOH_SERVER = "https://cloudflare-dns.com/dns-query"


def _ips_from_answer(domain: str, answer: List[Dict[str, Any]]) -> Set[str]:
    found_ips = set()
    for entry in answer:
        if entry["name"] != domain:
            continue

        # A records
        if entry["type"] == 1:
            # If we receive an A record, it has the following format:
            # {"name":"kazet.cc","type":1,"TTL":3600,"data":"213.32.88.99"}
            # Therefore the IP we want is in "data".
            found_ips.add(entry["data"])

        # CNAME
        if entry["type"] == 5:
            # If we receive a CNAME record, it points to another domain, e.g.:
            # {"name":"ftp.kazet.cc","type":5,"TTL":3600,"data":"kazet.cc."}
            #
            # So this is not the IP we want - we want to check *other records*
            # for the IP - so we cut the trailing dot (kazet.cc. -> kazet.cc) and
            # look for this domain in other records.
            for subentry in answer:
                if subentry["name"] == entry["data"].rstrip(".") and subentry["type"] == 1:
                    found_ips.add(subentry["data"])

    return found_ips


def ip_lookup(domain: str) -> Set[str]:
    """
    :return List of IP addresses

    :raise RuntimeError if something fails
    """
    response = requests.get(f"{DOH_SERVER}?name={domain}&type=A", headers={"accept": "application/dns-json"})
    if not response.ok:
        raise RuntimeError(f"DOH server invalid response ({response.status_code})")

    result = response.json()
    dns_rc = result["Status"]  # https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
    if dns_rc == 0:
        return _ips_from_answer(domain, result["Answer"])
    elif dns_rc == 3:  # NXDomain
        return set()
    else:
        raise RuntimeError(f"Unexpected DNS status ({dns_rc})")
