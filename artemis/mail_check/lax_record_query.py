# This is a module to query record candidates to be displayed in the UI.
#
# If something is not a correct record, but looks like one, and checkdmarc
# tells there is no record, the candidate will be displayed.

from typing import List

import dns.resolver

# We import private _query_dns from checkdmarc to avoid code duplication, as we
# consider importing a private function to be a lesser evil than duplicating it.
from checkdmarc import _query_dns as query_dns  # type: ignore
from checkdmarc import get_base_domain

SIGNATURE_LOOKUP_LENGTH = 20


def lax_query_spf_record(domain: str) -> List[str]:
    try:
        records = query_dns(domain, "SPF")
        if records:
            return records  # type: ignore
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass

    records = []
    answers = query_dns(domain, "TXT")
    for answer in answers:
        if "spf" in answer[:SIGNATURE_LOOKUP_LENGTH].lower():
            records.append(answer)
    return records  # type: ignore


def lax_query_single_dmarc_record(domain: str) -> List[str]:
    target = "_dmarc.{0}".format(domain.lower())

    try:
        record_candidates = query_dns(target, "TXT")
        records = []

        for record in record_candidates:
            if "dmarc" in record[:SIGNATURE_LOOKUP_LENGTH].lower():
                records.append(record)
        return records

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []


def lax_query_dmarc_record(domain: str) -> List[str]:
    records = lax_query_single_dmarc_record(domain)
    if records:
        return records
    base_domain = get_base_domain(domain)
    if base_domain and domain != base_domain:
        return lax_query_single_dmarc_record(base_domain)
    return []
