import dataclasses
import datetime
import enum
import ipaddress
from typing import List, Optional, Union

import yaml

from artemis import utils
from artemis.domains import is_domain, is_subdomain
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType

logger = utils.build_logger(__name__)


class UnsupportedBlocklistItem(Exception):
    pass


class BlocklistMode(str, enum.Enum):
    BLOCK_SCANNING_AND_REPORTING = "block_scanning_and_reporting"
    BLOCK_REPORTING_ONLY = "block_reporting_only"


@dataclasses.dataclass
class BlocklistItem:
    # each BlocklistItem is a filter that:
    # - if `mode` is block_scanning_and_reporting, blocks scanning as well as reporting. If `mode` is
    #   block_reporting_only, blocks only reporting,
    # - matches all the non-null items: domain_and_subdomains, ip_range, ...
    # - if all match, report/scanning is skipped.
    # The same is repeated for all BlocklistItems - if at least one matches, report/scanning is skipped.
    mode: BlocklistMode
    domain_only: Optional[str] = None
    domain_and_subdomains: Optional[str] = None
    subdomains: Optional[str] = None
    ip_range: Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = None
    until: Optional[datetime.datetime] = None
    karton_name: Optional[str] = None
    report_target_should_contain: Optional[str] = None
    report_type: Optional[ReportType] = None
    nuclei_template_names: Optional[List[str]] = None


class BlocklistError(Exception):
    pass


def load_blocklist(file_path: Optional[str]) -> List[BlocklistItem]:
    if not file_path:
        return []

    with open(file_path, "r") as file:
        data = yaml.safe_load(file)

    expected_keys = {
        "mode",
        "domain_and_subdomains",
        "domain_only",
        "subdomains",
        "ip_range",
        "until",
        "karton_name",
        "report_target_should_contain",
        "report_type",
        "nuclei_template_names",
    }

    for item in data:
        # Assert there are no additional keys
        unexpected_keys = set(item.keys()) - expected_keys
        if unexpected_keys:
            raise BlocklistError(f"Unexpected keys in entry: {','.join(unexpected_keys)}")

        if "karton_name" in item and item["karton_name"] == "classifier":
            raise BlocklistError(
                "It's not possible to blocklist classifier, as blocklists block IPs or domains, "
                "and classifier supports various input types (e.g. IP ranges converting them to IPs)."
            )

    blocklist_items = [
        BlocklistItem(
            mode=BlocklistMode(item["mode"]),
            domain_and_subdomains=item.get("domain_and_subdomains", None),
            domain_only=item.get("domain_only", None),
            subdomains=item.get("subdomains", None),
            ip_range=ipaddress.ip_network(item["ip_range"], strict=False) if item.get("ip_range", None) else None,
            until=datetime.datetime.strptime(item["until"], "%Y-%m-%d") if item.get("until", None) else None,
            karton_name=item.get("karton_name", None),
            report_target_should_contain=item.get("report_target_should_contain", None),
            report_type=item.get("report_type", None),
            nuclei_template_names=item.get("nuclei_template_names", None),
        )
        for item in data
    ]

    return blocklist_items


def should_block_scanning(
    domain: Optional[str], ip: Optional[str], karton_name: str, blocklist: List[BlocklistItem]
) -> bool:
    logger.info("checking whether scanning of domain=%s ip=%s by %s is filtered", domain, ip, karton_name)
    for item in blocklist:
        if item.mode != BlocklistMode.BLOCK_SCANNING_AND_REPORTING:
            continue

        if item.domain_only:
            if not domain:
                continue
            if domain != item.domain_only:
                continue

        if item.domain_and_subdomains:
            if not domain:
                continue
            if not is_subdomain(domain, item.domain_and_subdomains):
                continue

        if item.subdomains:
            if not domain:
                continue
            if not is_subdomain(domain, item.subdomains, allow_equal=False):
                continue

        if item.ip_range:
            if not ip:
                continue
            if ipaddress.IPv4Address(ip) not in item.ip_range:
                continue

        if item.until:
            if datetime.datetime.now() >= item.until:
                continue

        if item.karton_name and karton_name != item.karton_name:
            continue

        if item.report_target_should_contain:
            raise UnsupportedBlocklistItem(
                "If a blocklist item is set to block scanning, report_target_should_contain "
                "cannot be provided, as the report targets are determined during e-mail report generation "
                "(https://artemis-scanner.readthedocs.io/en/latest/generating-emails.html) and "
                "a single scanning module can cause different targets to be generated (e.g. "
                "for files found by the bruter module, the target would be their url, such as "
                "https://example.com/wp-config.php.bak)."
            )

        if item.report_type:
            raise UnsupportedBlocklistItem(
                "If a blocklist item is set to block scanning, report type cannot be provided, as "
                "report types are determined during e-mail report generation "
                "(https://artemis-scanner.readthedocs.io/en/latest/generating-emails.html) and "
                "a single scanning module can cause different report types to be generated."
            )

        if item.nuclei_template_names:
            raise NotImplementedError()

        logger.info(
            "scanning of domain=%s ip=%s by %s filtered due to blocklist rule %s", domain, ip, karton_name, item
        )
        return True
    return False


def blocklist_reports(reports: List[Report], blocklist: List[BlocklistItem]) -> List[Report]:
    result = []
    for report in reports:
        filtered = False
        for item in blocklist:
            domain = report.top_level_target if is_domain(report.top_level_target) else None
            if report.last_domain:
                domain = report.last_domain

            if item.domain_only:
                if not domain:
                    continue
                if domain != item.domain_only:
                    continue

            if item.domain_and_subdomains:
                if not domain:
                    continue
                if not is_subdomain(domain, item.domain_and_subdomains):
                    continue

            if item.subdomains:
                if not domain:
                    continue
                if not is_subdomain(domain, item.subdomains, allow_equal=False):
                    continue

            if item.ip_range:
                if not report.target_ip:
                    continue
                if ipaddress.IPv4Address(report.target_ip) not in item.ip_range:
                    continue

            if item.until:
                if not report.timestamp:
                    continue
                if report.timestamp >= item.until:
                    continue

            if item.karton_name and report.original_karton_name != item.karton_name:
                continue

            if item.report_target_should_contain and item.report_target_should_contain not in report.target:
                continue

            if item.report_type and report.report_type != item.report_type:
                continue

            if item.nuclei_template_names:
                if report.report_type not in ["nuclei_vulnerability", "nuclei_exposed_panel"]:
                    continue
                if (
                    report.additional_data["template_name"] not in item.nuclei_template_names
                    and report.additional_data["original_template_name"] not in item.nuclei_template_names
                ):
                    continue

            filtered = True
            logger.info(
                "report from %s (type=%s) in %s filtered due to blocklist rule %s",
                report.original_karton_name,
                report.report_type,
                report.target,
                item,
            )

        if not filtered:
            result.append(report)
    return result
