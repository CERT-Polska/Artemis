import functools
from typing import Set

import dns
from dns.resolver import Answer

from artemis.retrying_resolver import retry


class ResolutionException(Exception):
    pass


class NoAnswer(Exception):
    pass


def _results_from_answer(domain: str, answer: Answer, result_type: int) -> Set[str]:
    found_results = set()
    response = answer.response

    for entry in response.answer:
        if str(entry.name).rstrip(".") != domain:
            continue

        if entry.rdtype == result_type:
            found_results.add(entry.to_text().split(" ")[-1].rstrip("."))

        # CNAME
        if entry.rdtype == 5:
            # This is not the IP we want - we want to check *other records*
            # for the IP - so we cut the trailing dot (kazet.cc. -> kazet.cc) and
            # look for this domain in other records.
            for subentry in entry.to_rdataset():
                if (
                    subentry.to_text().split(" ")[-1].rstrip(".") == entry.to_text().split(" ")[-1].rstrip(".")
                    and subentry.rdtype == 1
                ):
                    found_results.add(subentry.to_text().rstrip("."))

    return found_results


def _single_resolution_attempt(domain: str, query_type: str = "A") -> Set[str]:
    try:
        answer = dns.resolver.resolve(domain, query_type)
        if dns.rcode.to_text(answer.response.rcode()) == "NOERROR":
            if query_type == "A":
                result_type = 1
            elif query_type == "NS":
                result_type = 2
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
    :return List of IP addresses (or domains, for NS lookup)

    :raise ResolutionException if something fails
    """
    try:
        return retry(_single_resolution_attempt, (domain, query_type), {})  # type: ignore
    except NoAnswer:
        return set()
