import datetime
import ipaddress
import unittest

from artemis.blocklist import (
    BlocklistItem,
    BlocklistMode,
    blocklist_reports,
    should_block_scanning,
)
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType


class ScanningBlocklistTest(unittest.TestCase):
    def test_ip_range_matching(self) -> None:
        blocklist_item1 = BlocklistItem(
            mode=BlocklistMode.BLOCK_SCANNING_AND_REPORTING,
            ip_range=ipaddress.ip_network("1.1.1.1/32", strict=False),
        )
        self.assertEqual(should_block_scanning(None, "1.1.1.2", "karton-name", [blocklist_item1]), False)
        self.assertEqual(should_block_scanning(None, "1.1.1.1", "karton-name", [blocklist_item1]), True)

    def test_domain_only_matching(self) -> None:
        blocklist_item1 = BlocklistItem(
            mode=BlocklistMode.BLOCK_SCANNING_AND_REPORTING,
            domain_only="example.com",
        )
        self.assertEqual(should_block_scanning("other.com", None, "karton-name", [blocklist_item1]), False)
        self.assertEqual(should_block_scanning("example.com", None, "karton-name", [blocklist_item1]), True)
        self.assertEqual(should_block_scanning("www.example.com", None, "karton-name", [blocklist_item1]), False)

    def test_domain_matching(self) -> None:
        blocklist_item1 = BlocklistItem(
            mode=BlocklistMode.BLOCK_SCANNING_AND_REPORTING,
            domain_and_subdomains="example.com",
        )
        self.assertEqual(should_block_scanning("other.com", None, "karton-name", [blocklist_item1]), False)
        self.assertEqual(should_block_scanning("example.com", None, "karton-name", [blocklist_item1]), True)
        self.assertEqual(should_block_scanning("www.example.com", None, "karton-name", [blocklist_item1]), True)

    def test_subdomain_matching(self) -> None:
        blocklist_item1 = BlocklistItem(
            mode=BlocklistMode.BLOCK_SCANNING_AND_REPORTING,
            subdomains="example.com",
        )
        self.assertEqual(should_block_scanning("other.com", None, "karton-name", [blocklist_item1]), False)
        self.assertEqual(should_block_scanning("example.com", None, "karton-name", [blocklist_item1]), False)
        self.assertEqual(should_block_scanning("www.example.com", None, "karton-name", [blocklist_item1]), True)

    def test_karton_name_matching(self) -> None:
        blocklist_item1 = BlocklistItem(
            mode=BlocklistMode.BLOCK_SCANNING_AND_REPORTING,
            karton_name="bruter",
        )
        self.assertEqual(should_block_scanning(None, None, "nuclei", [blocklist_item1]), False)
        self.assertEqual(should_block_scanning(None, None, "bruter", [blocklist_item1]), True)

    def test_expiry(self) -> None:
        blocklist_item1 = BlocklistItem(
            mode=BlocklistMode.BLOCK_SCANNING_AND_REPORTING,
            until=datetime.datetime(2023, 1, 9),
        )
        self.assertEqual(should_block_scanning("domain.com", "1.1.1.1", "nuclei", [blocklist_item1]), False)
        blocklist_item2 = BlocklistItem(
            mode=BlocklistMode.BLOCK_SCANNING_AND_REPORTING,
            until=datetime.datetime(2999, 1, 9),
        )
        self.assertEqual(should_block_scanning("domain.com", "1.1.1.1", "nuclei", [blocklist_item2]), True)


class ReportBlocklistTest(unittest.TestCase):
    def test_target_matching(self) -> None:
        report1 = Report(
            target="http://example.com/url1/",
            report_type=ReportType("exposed_configuration_file"),
            top_level_target="example.com",
            additional_data={},
        )
        report2 = Report(
            target="http://example.com/url2/",
            report_type=ReportType("exposed_configuration_file"),
            top_level_target="example.com",
            additional_data={},
        )
        blocklist_item = BlocklistItem(
            mode=BlocklistMode.BLOCK_SCANNING_AND_REPORTING, report_target_should_contain="/url1"
        )
        self.assertEqual(blocklist_reports([report1, report2], [blocklist_item]), [report2])

    def test_ip_range_matching(self) -> None:
        report1 = Report(
            target="http://example.com/",
            target_ip="1.1.1.1",
            target_ip_checked=True,
            report_type=ReportType("exposed_configuration_file"),
            top_level_target="example.com",
            additional_data={},
        )
        report2 = Report(
            target="http://example.com/",
            target_ip="1.1.1.2",
            target_ip_checked=True,
            report_type=ReportType("exposed_configuration_file"),
            top_level_target="example.com",
            additional_data={},
        )
        blocklist_item1 = BlocklistItem(
            mode=BlocklistMode.BLOCK_SCANNING_AND_REPORTING,
            ip_range=ipaddress.ip_network("1.1.1.1/32", strict=False),
        )
        self.assertEqual(blocklist_reports([report1, report2], [blocklist_item1]), [report2])
        blocklist_item2 = BlocklistItem(
            mode=BlocklistMode.BLOCK_SCANNING_AND_REPORTING,
            ip_range=ipaddress.ip_network("1.0.0.0/8", strict=False),
        )
        self.assertEqual(blocklist_reports([report1, report2], [blocklist_item2]), [])

    def test_domain_matching(self) -> None:
        report1 = Report(
            target="http://example.com/",
            top_level_target="example.com",
            report_type=ReportType("exposed_configuration_file"),
            additional_data={},
        )
        report2 = Report(
            target="http://ftp.example.com/",
            top_level_target="ftp.example.com",
            report_type=ReportType("exposed_configuration_file"),
            additional_data={},
        )
        blocklist_item = BlocklistItem(
            mode=BlocklistMode.BLOCK_SCANNING_AND_REPORTING,
            domain_only="example.com",
        )
        self.assertEqual(blocklist_reports([report1, report2], [blocklist_item]), [report2])

        report1 = Report(
            target="http://example.com/",
            top_level_target="www.example.com",
            report_type=ReportType("exposed_configuration_file"),
            additional_data={},
        )
        report2 = Report(
            target="http://example.com/",
            top_level_target="ftp.example.com",
            report_type=ReportType("exposed_configuration_file"),
            additional_data={},
        )
        blocklist_item = BlocklistItem(
            mode=BlocklistMode.BLOCK_SCANNING_AND_REPORTING,
            domain_and_subdomains="www.example.com",
        )
        self.assertEqual(blocklist_reports([report1, report2], [blocklist_item]), [report2])

        report1 = Report(
            target="http://example.com/",
            last_domain="www.example.com",
            top_level_target="example.com",
            report_type=ReportType("exposed_configuration_file"),
            additional_data={},
        )
        report2 = Report(
            target="http://example.com/",
            last_domain="ftp.example.com",
            top_level_target="example.com",
            report_type=ReportType("exposed_configuration_file"),
            additional_data={},
        )
        blocklist_item = BlocklistItem(
            mode=BlocklistMode.BLOCK_SCANNING_AND_REPORTING,
            domain_and_subdomains="www.example.com",
        )
        self.assertEqual(blocklist_reports([report1, report2], [blocklist_item]), [report2])

    def test_report_type_matching(self) -> None:
        report1 = Report(
            target="example.com",
            top_level_target="www.example.com",
            report_type=ReportType("zone_transfer_possible"),
            additional_data={},
        )
        report2 = Report(
            target="http://example.com/",
            top_level_target="ftp.example.com",
            report_type=ReportType("exposed_configuration_file"),
            additional_data={},
        )
        blocklist_item = BlocklistItem(
            mode=BlocklistMode.BLOCK_SCANNING_AND_REPORTING,
            report_type=ReportType("zone_transfer_possible"),
        )
        self.assertEqual(blocklist_reports([report1, report2], [blocklist_item]), [report2])

    def test_expiry(self) -> None:
        report1 = Report(
            target="http://example.com/1",
            top_level_target="example.com",
            timestamp=datetime.datetime(2023, 1, 1),
            report_type=ReportType("exposed_configuration_file"),
            additional_data={},
        )
        report2 = Report(
            target="http://example.com/2",
            top_level_target="example.com",
            timestamp=datetime.datetime(2023, 1, 10),
            report_type=ReportType("exposed_configuration_file"),
            additional_data={},
        )
        blocklist_item = BlocklistItem(
            mode=BlocklistMode.BLOCK_SCANNING_AND_REPORTING,
            report_type=ReportType("exposed_configuration_file"),
            until=datetime.datetime(2023, 1, 9),
        )
        self.assertEqual(blocklist_reports([report1, report2], [blocklist_item]), [report2])
