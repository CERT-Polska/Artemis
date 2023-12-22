import functools
from typing import Any, Dict, List, Set

import requests

from artemis.retrying_resolver import retry

DOH_SERVER = "https://cloudflare-dns.com/dns-query"


class ResolutionException(Exception):
    pass


class NoAnswer(Exception):
    pass


def _results_from_answer(domain: str, answer: List[Dict[str, Any]], result_type: int) -> Set[str]:
    found_results = set()
    for entry in answer:
        if entry["name"] != domain:
            continue

        if entry["type"] == result_type:
            # If we receive an A record, it has the following format:
            # {"name":"cert.pl","type":1,"TTL":3600,"data":"[ ip ]"}
            # If we receive a NS record, it has the following format:
            # {"name":"cert.pl","type':2,"TTL":1800,"data":"[ domain ]"}
            # Therefore the result we want is in "data".
            found_results.add(entry["data"].strip("."))

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
                    found_results.add(subentry["data"])

    return found_results


def _single_resolution_attempt(domain: str, query_type: str = "A") -> Set[str]:
    response = requests.get(
        f"{DOH_SERVER}?name={domain.encode('idna').decode('ascii')}&type={query_type}",
        headers={"accept": "application/dns-json"},
    )
    if not response.ok:
        raise ResolutionException(f"DOH server invalid response ({response.status_code})")

    result = response.json()
    dns_rc = result["Status"]  # https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
    if dns_rc == 0:
        if "Answer" in result:
            if query_type == "A":
                result_type = 1
            elif query_type == "NS":
                result_type = 2
            else:
                raise NotImplementedError(f"Don't know how to obtain results for query {query_type}")

            return _results_from_answer(domain, result["Answer"], result_type)
        else:
            raise NoAnswer()
    elif dns_rc == 3:  # NXDomain
        return set()
    else:
        raise ResolutionException(f"Unexpected DNS status ({dns_rc})")


@functools.lru_cache(maxsize=8192)
def lookup(domain: str, query_type: str = "A") -> Set[str]:
    """
    :return List of IP addresses (or domains, for NS lookup)

    :raise ResolutionException if something fails
    """
    try:
        return retry(_single_resolution_attempt, (domain, query_type), {})  # type: ignore
    except NoAnswer:
        return set()
