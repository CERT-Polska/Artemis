import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import checkdmarc  # type: ignore


@dataclass
class SPFScanResult:
    dns_lookups: Optional[int]
    parsed: Optional[Dict[str, Any]]
    record: Optional[str]
    valid: bool
    errors: List[str]
    warnings: List[str]


@dataclass
class DMARCScanResult:
    location: Optional[str]
    tags: Optional[Dict[str, Any]]
    record: Optional[str]
    valid: bool
    errors: List[str]
    warnings: List[str]


@dataclass
class DomainScanResult:
    spf: SPFScanResult
    dmarc: DMARCScanResult
    domain: str
    base_domain: str


def contains_spf_all_fail(parsed: Dict[str, Any]) -> bool:
    if parsed["all"] in ["softfail", "fail"]:
        return True
    if "redirect" in parsed and parsed["redirect"]:
        return contains_spf_all_fail(parsed["redirect"]["parsed"])
    return False


def check_domain(
    domain: str,
    parked: bool = False,
    include_dmarc_tag_descriptions: bool = False,
    nameservers: Optional[List[str]] = None,
    timeout: float = 2.0,
) -> DomainScanResult:
    domain = domain.lower()
    logging.debug("Checking: {0}".format(domain))
    domain_result = DomainScanResult(
        spf=SPFScanResult(
            record=None,
            parsed=None,
            valid=True,
            dns_lookups=None,
            errors=[],
            warnings=[],
        ),
        dmarc=DMARCScanResult(record=None, tags=None, valid=True, location=None, errors=[], warnings=[]),
        domain=domain,
        base_domain=checkdmarc.get_base_domain(domain),
    )

    try:
        spf_query = checkdmarc.query_spf_record(domain, nameservers=nameservers, timeout=timeout)
        domain_result.spf.record = spf_query["record"]
        domain_result.spf.warnings = spf_query["warnings"]
        parsed_spf = checkdmarc.parse_spf_record(
            domain_result.spf.record,
            domain_result.domain,
            parked=parked,
            nameservers=nameservers,
            timeout=timeout,
        )
        domain_result.spf.dns_lookups = parsed_spf["dns_lookups"]
        domain_result.spf.parsed = parsed_spf["parsed"]
        domain_result.spf.warnings = list(set(domain_result.spf.warnings) | set(parsed_spf["warnings"]))

        if not contains_spf_all_fail(parsed_spf["parsed"]):
            domain_result.spf.errors = ["SPF ~all or -all directive not found"]
            domain_result.spf.valid = False
    except checkdmarc.SPFRecordNotFound:
        domain_result.spf.errors = ["SPF record not found"]
        domain_result.spf.valid = False
    except checkdmarc.SPFIncludeLoop:
        domain_result.spf.errors = ["SPF record includes an endless loop"]
        domain_result.spf.valid = False
    except checkdmarc.SPFRedirectLoop:
        domain_result.spf.errors = ["SPF record includes an endless loop"]
        domain_result.spf.valid = False
    except checkdmarc.SPFSyntaxError:
        domain_result.spf.errors = ["SPF record is not syntatically correct"]
        domain_result.spf.valid = False
    except checkdmarc.SPFTooManyDNSLookups:
        domain_result.spf.errors = ["SPF record includes too many DNS lookups"]
        domain_result.spf.valid = False

    # DMARC
    try:
        dmarc_query = checkdmarc.query_dmarc_record(domain, nameservers=nameservers, timeout=timeout)
        domain_result.dmarc.record = dmarc_query["record"]
        domain_result.dmarc.location = dmarc_query["location"]
        parsed_dmarc_record = checkdmarc.parse_dmarc_record(
            dmarc_query["record"],
            dmarc_query["location"],
            parked=parked,
            include_tag_descriptions=include_dmarc_tag_descriptions,
            nameservers=nameservers,
            timeout=timeout,
        )

        if parsed_dmarc_record["tags"]["p"]["value"] == "none":
            p_warnings = ["DMARC policy is none, which means that besides " "reporting no action will be taken"]
        else:
            p_warnings = []

        domain_result.dmarc.tags = parsed_dmarc_record["tags"]
        domain_result.dmarc.warnings = list(
            set(dmarc_query["warnings"]) | set(parsed_dmarc_record["warnings"]) | set(p_warnings)
        )
    except checkdmarc.DMARCRecordNotFound:
        domain_result.dmarc.errors = ["DMARC record not found"]
        domain_result.dmarc.valid = False
    except checkdmarc.DMARCRecordInWrongLocation:
        domain_result.dmarc.errors = ["DMARC record should be stored in the `_dmarc` subdomain"]
        domain_result.dmarc.valid = False
    except checkdmarc.MultipleDMARCRecords:
        domain_result.dmarc.errors = ["There are multiple DMARC records"]
        domain_result.dmarc.valid = False
    except checkdmarc.SPFRecordFoundWhereDMARCRecordShouldBe:
        domain_result.dmarc.errors = ["There is a SPF record instead of DMARC one"]
        domain_result.dmarc.valid = False
    except checkdmarc.DMARCSyntaxError:
        domain_result.dmarc.errors = ["DMARC record is not syntatically correct"]
        domain_result.dmarc.valid = False
    # except checkdmarc.InvalidDMARCTag:
    #     domain_result.dmarc.errors = ["SPF record includes an endless loop"]
    #     domain_result.dmarc.valid = False
    except checkdmarc.InvaliddDMARCTagValue:
        domain_result.dmarc.errors = ["DMARC record uses an invalid tag"]
        domain_result.dmarc.valid = False
    except checkdmarc.InvalidDMARCReportURI:
        domain_result.dmarc.errors = ["DMARC report URI is invalid"]
        domain_result.dmarc.valid = False
    except checkdmarc.UnverifiedDMARCURIDestination:
        domain_result.dmarc.errors = [
            "The destination of a DMARC report URI does not " "indicate that it accepts reports for the domain"
        ]
        domain_result.dmarc.valid = False
    except checkdmarc.UnrelatedTXTRecordFound:
        domain_result.dmarc.errors = ["Unrelated TXT record found"]
        domain_result.dmarc.valid = False
    except checkdmarc.DMARCReportEmailAddressMissingMXRecords:
        domain_result.dmarc.errors = ["A email address in a DMARC report URI is missing MX records"]
        domain_result.dmarc.valid = False

    return domain_result
