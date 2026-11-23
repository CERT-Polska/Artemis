import functools
import socket
from typing import Set

import dns
import dns.rdatatype
from dns.rdtypes.mxbase import MXBase
from dns.resolver import Answer

from artemis.retrying_resolver import retry


class ResolutionException(Exception):
    pass


class NoAnswer(Exception):
    pass


MAX_CNAME_NEST_DEPTH = 5


def _results_from_answer(domain: str, answer: Answer, result_type: int) -> Set[str]:
    found_results = []
    response = answer.response

    for entry in response.answer:
        if str(entry.name).rstrip(".") != domain:
            continue

        for item in entry.items:
            item = str(item).rstrip(".")

            if entry.rdtype == result_type:
                found_results.append(item)

            # CNAME
            if entry.rdtype == 5:
                for _ in range(MAX_CNAME_NEST_DEPTH):
                    # This is not the IP we want - we want to check *other records*
                    # for the IP - so we cut the trailing dot (kazet.cc. -> kazet.cc) and
                    # look for this domain in other records.
                    for subentry in response.answer:
                        if str(subentry.name).strip(".") == item and subentry.rdtype == 1:
                            found_results.append(subentry.to_text().split(" ")[-1].rstrip("."))
                            break

                        if str(subentry.name).strip(".") == item and subentry.rdtype == 2:
                            for rdataset in subentry:
                                found_results.append(rdataset.to_text().rstrip("."))
                            break

                        if str(subentry.name).strip(".") == item and subentry.rdtype == 5:
                            # CNAME refering to another CNAME record (this happens)
                            item = subentry.to_text().split(" ")[-1].rstrip(".")

    return set(found_results)


def _results_from_rrset(answer: Answer, query_type: str) -> Set[str]:
    """
    Returns the IPv6 addresses (AAAA) or mail server names (MX) from an answer. dnspython has
    already followed any CNAME chain, so answer.rrset holds the records of the final name.
    """
    rdtype = dns.rdatatype.from_text(query_type)
    # WrappedResolver answers an AAAA query for a name known to the system resolver with an
    # A record, so check the record type instead of trusting the query type.
    if answer.rrset is None or answer.rrset.rdtype != rdtype:
        return set()

    if rdtype == dns.rdatatype.MX:
        # A null MX (RFC 7505) points at the root, ".": keep it rather than an empty name.
        return {rdata.exchange.to_text().rstrip(".") or "." for rdata in answer.rrset if isinstance(rdata, MXBase)}
    return {rdata.to_text() for rdata in answer.rrset}


def _single_resolution_attempt(domain: str, query_type: str = "A") -> Set[str]:
    try:
        answer = dns.resolver.resolve(domain, query_type)

        if query_type == "A":
            result_type = 1
        elif query_type == "NS":
            result_type = 2
        elif query_type in ["AAAA", "MX"]:
            return _results_from_rrset(answer, query_type)
        else:
            raise NotImplementedError(f"Don't know how to obtain results for query {query_type}")
        return _results_from_answer(domain, answer, result_type)

    except dns.resolver.NoAnswer:
        raise NoAnswer()
    except dns.resolver.NXDOMAIN:
        return set()
    except Exception as e:
        raise ResolutionException(f"Unexpected DNS status ({e})")


@functools.lru_cache(maxsize=8192)
def lookup(domain: str, query_type: str = "A") -> Set[str]:
    """
    :return List of IP addresses (or domains, for NS and MX lookups)

    :raise ResolutionException if something fails
    """
    if query_type == "A":
        try:
            # First try socket.gethostbyname to lookup from hosts file
            return {socket.gethostbyname(domain)}
        except socket.gaierror:
            pass
    try:
        domain = domain.lower()
        return retry(_single_resolution_attempt, (domain, query_type), {})  # type: ignore
    except NoAnswer:
        return set()
