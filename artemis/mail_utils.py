import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import checkdmarc  # type: ignore
import dns.resolver


@dataclass
class SPFScanResult:
    dns_lookups: Optional[int]
    parsed: Optional[Dict[str, Any]]
    record: Optional[str]
    # As this error is interpreted in a special way by downstream tools,
    # let's have a flag (not only a string message) whether it happened.
    record_not_found: bool
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


class ScanningException(Exception):
    def __init__(self, message: str) -> None:
        self.message = message


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
    timeout: float = 5.0,
    ignore_void_dns_lookups: bool = False,
) -> DomainScanResult:
    domain = domain.lower()
    logging.debug("Checking: {0}".format(domain))
    domain_result = DomainScanResult(
        spf=SPFScanResult(
            record=None,
            parsed=None,
            valid=True,
            dns_lookups=None,
            record_not_found=False,
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

        try:
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
            # This is a different type from standard SPFRecordNotFound - it occurs
            # during *parsing*, so it is not caused by lack of SPF record, but
            # a malformed one (e.g. including a domain that doesn't have a SPF record).
            domain_result.spf.errors = ["SPF record not found in domain referenced from other SPF record"]
            domain_result.spf.valid = False
    except checkdmarc.SPFRecordNotFound as e:
        # https://github.com/domainaware/checkdmarc/issues/90
        if isinstance(e.args[0], dns.exception.DNSException):
            raise ScanningException(e.args[0].msg if e.args[0].msg else repr(e.args[0]))  # type: ignore

        domain_result.spf.errors = ["SPF record not found"]
        domain_result.spf.record_not_found = True
        domain_result.spf.valid = False
    except checkdmarc.SPFTooManyVoidDNSLookups:
        if not ignore_void_dns_lookups:
            domain_result.spf.errors = ["SPF record causes too many void DNS lookups"]
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
            if "rua" not in parsed_dmarc_record["tags"]:
                domain_result.dmarc.errors = [
                    "DMARC policy is none and rua is not set, which " "means that the DMARC setting is not effective."
                ]
                domain_result.dmarc.valid = False
                p_warnings = []
            else:
                p_warnings = ["DMARC policy is none, which means that besides " "reporting no action will be taken"]
        else:
            p_warnings = []

        domain_result.dmarc.tags = parsed_dmarc_record["tags"]
        domain_result.dmarc.warnings = list(
            set(dmarc_query["warnings"]) | set(parsed_dmarc_record["warnings"]) | set(p_warnings)
        )
    except checkdmarc.DMARCRecordNotFound as e:
        # https://github.com/domainaware/checkdmarc/issues/90
        if isinstance(e.args[0], dns.exception.DNSException):
            raise ScanningException(e.args[0].msg if e.args[0].msg else repr(e.args[0]))  # type: ignore

        # Before https://github.com/domainaware/checkdmarc/issues/91 gets done,
        # UnrelatedTXTRecordFoundAtDMARC blocks further checks and we are not able to
        # check whether the record is indeed valid. Therefore for now let's assume it
        # is so that no false positive "not found" error is returned.
        if isinstance(e.args[0], checkdmarc.UnrelatedTXTRecordFoundAtDMARC):
            domain_result.dmarc.warnings = ["Unrelated TXT record found"]
            domain_result.dmarc.valid = True
        else:
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
    except checkdmarc.InvalidDMARCTagValue:
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
    except checkdmarc.UnrelatedTXTRecordFoundAtDMARC:
        domain_result.dmarc.errors = ["Unrelated TXT record found"]
        domain_result.dmarc.valid = False
    except checkdmarc.DMARCReportEmailAddressMissingMXRecords:
        domain_result.dmarc.errors = ["A email address in a DMARC report URI is missing MX records"]
        domain_result.dmarc.valid = False

    return domain_result
