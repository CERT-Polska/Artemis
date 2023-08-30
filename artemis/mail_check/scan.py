import datetime
import io
import logging
import string
from dataclasses import dataclass
from email import message_from_file
from typing import Any, Dict, List, Optional

import checkdmarc  # type: ignore
import dkim
import dns.resolver
import publicsuffixlist
import validators

checkdmarc.DNS_CACHE.max_age = 1
checkdmarc.TLS_CACHE.max_age = 1
checkdmarc.STARTTLS_CACHE.max_age = 1

psl = publicsuffixlist.PublicSuffixList()


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
    warnings: List[str]


@dataclass
class DKIMScanResult:
    valid: bool
    errors: List[str]
    warnings: List[str]


@dataclass
class ScanResult:
    domain: Optional[DomainScanResult]
    dkim: Optional[DKIMScanResult]
    timestamp: Optional[datetime.datetime]
    message_timestamp: Optional[datetime.datetime]

    @property
    def num_checked_mechanisms(self) -> int:
        result = 0
        if self.domain:
            result += 2
        if self.dkim:
            result += 1
        return result

    @property
    def num_correct_mechanisms(self) -> int:
        result = 0
        for mechanism in self.mechanisms:
            if mechanism.valid and not mechanism.warnings:
                result += 1
        return result

    @property
    def has_not_valid_mechanisms(self) -> int:
        for mechanism in self.mechanisms:
            if not mechanism.valid:
                return True
        return False

    @property
    def mechanisms(self) -> List[Any]:
        mechanisms: List[Any] = []
        if self.domain:
            mechanisms.append(self.domain.spf)
            mechanisms.append(self.domain.dmarc)

        if self.dkim:
            mechanisms.append(self.dkim)
        return mechanisms


class ScanningException(Exception):
    def __init__(self, message: str) -> None:
        self.message = message


class DomainValidationException(Exception):
    def __init__(self, message: str):
        self.message = message


def validate_and_sanitize_domain(domain: str) -> str:
    domain = domain.lower().strip(" .")

    for space in string.whitespace:
        if space in domain:
            raise DomainValidationException("Whitespace in domain name detected. Please provide a correct domain name.")
    for forbidden_character in set(string.punctuation) - {".", "-"}:
        if forbidden_character in domain:
            raise DomainValidationException(
                f"Unexpected character in domain detected: {forbidden_character}. Please provide a correct domain name."
            )

    result = validators.domain(domain)
    if isinstance(result, validators.ValidationError):
        raise DomainValidationException("Please provide a correct domain name.")

    return domain


def contains_spf_all_fail(parsed: Dict[str, Any]) -> bool:
    if parsed["all"] in ["softfail", "fail"]:
        return True
    if "redirect" in parsed and parsed["redirect"]:
        return contains_spf_all_fail(parsed["redirect"]["parsed"])
    return False


def scan_domain(
    domain: str,
    parked: bool = False,
    nameservers: Optional[List[str]] = None,
    include_dmarc_tag_descriptions: bool = False,
    timeout: float = 10.0,
    ignore_void_dns_lookups: bool = False,
) -> DomainScanResult:
    domain = validate_and_sanitize_domain(domain)

    warnings = []
    # We glue example-subdomain. to the domain due to the behavior of the publicsuffixlist library - if
    # accept_unknown is False, the publicsuffix() of a *known* TLD would be None.
    if psl.publicsuffix("example-subdomain." + domain, accept_unknown=False) == domain:
        warnings.append(
            "Requested to scan a domain that is a public suffix, i.e. a domain such as .com where anybody could "
            "register their subdomain. Such domain don't have to have properly configured e-mail sender verification "
            "mechanisms. Please make sure you really wanted to check such domain and not its subdomain.",
        )
    elif psl.publicsuffix("example-subdomain." + domain) == domain:
        warnings.append(
            "Requested to scan a top-level domain. Top-level domains don't have to have properly configured e-mail sender "
            "verification mechanisms. Please make sure you really wanted to check such domain and not its subdomain."
            "Besides, the domain is not known to the Public Suffix List (https://publicsuffix.org/) - please verify whether "
            "it is correct.",
        )

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
        warnings=warnings,
    )

    try:
        spf_query = checkdmarc.query_spf_record(domain, nameservers=nameservers, timeout=timeout)

        domain_result.spf.record = spf_query["record"]
        if domain_result.spf.record and "%" in domain_result.spf.record:
            domain_result.spf.warnings = ["SPF records containing macros aren't supported yet."]
            domain_result.spf.valid = False
        elif not domain_result.spf.record:
            raise checkdmarc.SPFRecordNotFound(None)
        else:
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
                    domain_result.spf.errors = [
                        "SPF '~all' or '-all' directive not found. We recommend adding it, as it describes "
                        "what should happen with messages that fail SPF verification. For example, "
                        "'-all' will tell the recipient server to drop such messages."
                    ]
                    domain_result.spf.valid = False
            except checkdmarc.SPFRecordNotFound:
                # This is a different type from standard SPFRecordNotFound - it occurs
                # during *parsing*, so it is not caused by lack of SPF record, but
                # a malformed one (e.g. including a domain that doesn't have a SPF record).
                domain_result.spf.errors = [
                    "The SPF record references a domain that doesn't have an SPF record. When using directives such "
                    "as 'include' or 'redirect', remember, that the destination domain should have a proper SPF record.",
                ]
                domain_result.spf.valid = False
    except checkdmarc.SPFRecordNotFound as e:
        # https://github.com/domainaware/checkdmarc/issues/90
        if isinstance(e.args[0], dns.exception.DNSException):
            raise ScanningException(e.args[0].msg if e.args[0].msg else repr(e.args[0]))

        if isinstance(e.args[0], checkdmarc.MultipleSPFRTXTRecords):
            domain_result.spf.errors = [
                "Multiple SPF records found. We recommend leaving only one, as multiple SPF records "
                "can cause problems with some SPF implementations.",
            ]
            domain_result.spf.valid = False
        else:
            # Sometimes an entry pretending to be a SPF record exists (e.g. something
            # beginning with [space]v=spf1) so to avoid communication problems
            # with the user we tell them that we didn't find a valid one.
            domain_result.spf.errors = [
                "Valid SPF record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC "
                "to decrease the possibility of successful e-mail message spoofing.",
            ]
            domain_result.spf.record_not_found = True
            domain_result.spf.valid = False
    except checkdmarc.SPFTooManyVoidDNSLookups:
        if not ignore_void_dns_lookups:
            domain_result.spf.errors = [
                "SPF record causes too many void DNS lookups. Some implementations may require the number of "
                "failed DNS lookups (e.g. ones that reference a nonexistent domain) to be low. The DNS lookups "
                "are caused by directives such as 'mx' or 'include'.",
            ]
            domain_result.spf.valid = False
    except checkdmarc.SPFIncludeLoop:
        domain_result.spf.errors = [
            "SPF record includes an endless loop. Please check whether 'include' or 'redirect' directives don't "
            "create a loop where a domain redirects back to itself or earlier domain."
        ]
        domain_result.spf.valid = False
    except checkdmarc.SPFRedirectLoop:
        domain_result.spf.errors = [
            "SPF record includes an endless loop. Please check whether 'include' or 'redirect' directives don't "
            "create a loop where a domain redirects back to itself or earlier domain."
        ]
        domain_result.spf.valid = False
    except checkdmarc.SPFSyntaxError:
        domain_result.spf.errors = ["SPF record is not syntactically correct. Please closely inspect its syntax."]
        domain_result.spf.valid = False
    except checkdmarc.SPFTooManyDNSLookups:
        domain_result.spf.errors = [
            "SPF record causes too many DNS lookups. The DNS lookups are caused by directives such as 'mx' or 'include'. "
            "The specification requires the number of DNS lookups to be lower or equal to 10 to decrease load on DNS servers.",
        ]
        domain_result.spf.valid = False

    # DMARC
    try:
        dmarc_warnings = []

        try:
            dmarc_query = checkdmarc.query_dmarc_record(domain, nameservers=nameservers, timeout=timeout)
        except checkdmarc.DMARCRecordNotFound as e:
            if isinstance(e.args[0], checkdmarc.UnrelatedTXTRecordFoundAtDMARC):
                dmarc_warnings.append(
                    "Unrelated TXT record found in the '_dmarc' subdomain. We recommend removing it, as such unrelated "
                    "records may cause problems with some DMARC implementations.",
                )
                dmarc_query = checkdmarc.query_dmarc_record(
                    domain,
                    nameservers=nameservers,
                    timeout=timeout,
                    raise_for_unrelated_records=False,
                )
            else:
                raise e
        domain_result.dmarc.record = dmarc_query["record"]
        if not domain_result.dmarc.record:
            raise checkdmarc.DMARCRecordNotFound(None)

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
                    "DMARC policy is 'none' and 'rua' is not set, which means that the DMARC setting is not effective."
                ]
                domain_result.dmarc.valid = False
            else:
                dmarc_warnings.append(
                    "DMARC policy is 'none', which means that besides reporting no action will be taken. The policy describes what "
                    "action the recipient server should take when noticing a message that doesn't pass the verification. 'quarantine' policy "
                    "suggests the recipient server to flag the message as spam and 'reject' policy suggests the recipient "
                    "server to reject the message. We recommend using the 'quarantine' or 'reject' policy.",
                )

        domain_result.dmarc.tags = parsed_dmarc_record["tags"]
        domain_result.dmarc.warnings = list(
            set(dmarc_query["warnings"]) | set(parsed_dmarc_record["warnings"]) | set(dmarc_warnings)
        )
    except checkdmarc.DMARCRecordNotFound as e:
        # https://github.com/domainaware/checkdmarc/issues/90
        if isinstance(e.args[0], dns.exception.DNSException):
            raise ScanningException(e.args[0].msg if e.args[0].msg else repr(e.args[0]))

        # Sometimes an entry pretending to be a DMARC record exists so to avoid
        # communication problems with the user we tell them that we
        # didn't find a valid one.
        domain_result.dmarc.errors = [
            "Valid DMARC record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC "
            "to decrease the possibility of successful e-mail message spoofing.",
        ]
        domain_result.dmarc.valid = False
    except checkdmarc.DMARCRecordInWrongLocation as e:
        # We put here the original exception message from checkdmarc ("The DMARC record must be located at {0},
        # not {1}") as it contains the domain names describing the expected and actual location.
        domain_result.dmarc.errors = [e.args[0]]
        domain_result.dmarc.valid = False
    except checkdmarc.MultipleDMARCRecords:
        domain_result.dmarc.errors = [
            "There are multiple DMARC records. We recommend leaving only one, as multiple "
            "DMARC records can cause problems with some DMARC implementations.",
        ]
        domain_result.dmarc.valid = False
    except checkdmarc.SPFRecordFoundWhereDMARCRecordShouldBe:
        domain_result.dmarc.errors = [
            "There is a SPF record instead of DMARC one on the '_dmarc' subdomain.",
        ]
        domain_result.dmarc.valid = False
    except checkdmarc.DMARCRecordStartsWithWhitespace:
        domain_result.dmarc.errors = [
            "Found a DMARC record that starts with whitespace. "
            "Please remove the whitespace, as some implementations may not "
            "process it correctly."
        ]
        domain_result.dmarc.valid = False
    except checkdmarc.DMARCSyntaxError:
        domain_result.dmarc.errors = [
            "DMARC record is not syntactically correct. Please closely inspect its syntax.",
        ]
        domain_result.dmarc.valid = False
    except checkdmarc.InvalidDMARCTag:
        domain_result.dmarc.errors = [
            "DMARC record uses an invalid tag. Please refer to https://datatracker.ietf.org/doc/html/rfc7489#section-6.3 "
            "for the list of available tags."
        ]
        domain_result.dmarc.valid = False
    except checkdmarc.InvalidDMARCReportURI:
        domain_result.dmarc.errors = [
            "DMARC report URI is invalid. The report URI should be an e-mail address prefixed with mailto:.",
        ]
        domain_result.dmarc.valid = False
    except checkdmarc.UnverifiedDMARCURIDestination:
        domain_result.dmarc.errors = [
            "The destination of a DMARC report URI does not " "indicate that it accepts reports for the domain."
        ]
        domain_result.dmarc.valid = False
    except checkdmarc.UnrelatedTXTRecordFoundAtDMARC:
        domain_result.dmarc.warnings = [
            "Unrelated TXT record found in the '_dmarc' subdomain - further verification can be performed after removing them."
        ]
        domain_result.dmarc.valid = False
    except checkdmarc.DMARCReportEmailAddressMissingMXRecords:
        domain_result.dmarc.errors = [
            "The domain of the email address in a DMARC report URI is missing MX records. That means, that this domain "
            "may not receive DMARC reports."
        ]
        domain_result.dmarc.valid = False

    return domain_result


def scan_dkim(
    message: bytes,
) -> DKIMScanResult:
    stream = io.StringIO(message.decode("ascii", errors="ignore"))
    message_parsed = message_from_file(stream)
    if "dkim-signature" not in message_parsed:
        return DKIMScanResult(
            valid=False,
            errors=["No DKIM signature found"],
            warnings=[],
        )
    try:
        if dkim.verify(message):
            return DKIMScanResult(
                valid=True,
                errors=[],
                warnings=[],
            )
        else:
            return DKIMScanResult(
                valid=False,
                errors=["Found an invalid DKIM signature"],
                warnings=[],
            )
    except dkim.DKIMException as e:
        return DKIMScanResult(
            valid=False,
            errors=[e.message],
            warnings=[],
        )


def scan(
    domain: str,
    message: Optional[bytes],
    message_timestamp: Optional[datetime.datetime],
    nameservers: Optional[List[str]] = None,
) -> ScanResult:
    return ScanResult(
        domain=scan_domain(
            domain=domain,
            nameservers=nameservers,
        ),
        dkim=scan_dkim(
            message=message,
        )
        if message
        else None,
        timestamp=datetime.datetime.now(),
        message_timestamp=message_timestamp,
    )
