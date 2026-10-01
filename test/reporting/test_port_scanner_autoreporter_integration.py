from test.base import BaseReportingTest
from typing import Any, Dict

from artemis.modules.port_scanner import PortScanner
from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.language import Language
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporters import (
    assets_from_task_result,
    reports_from_task_result,
)


class PortScannerAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = PortScanner  # type: ignore

    def test_asset_discovery(self) -> None:
        data = self.obtain_domain_task_result("port_scanner", "test-old-wordpress")
        assets = assets_from_task_result(data)
        self.assertEqual(
            assets,
            [
                Asset(
                    asset_type=AssetType.OPEN_PORT,
                    name="test-old-wordpress:80",
                    additional_type="http",
                ),
                Asset(asset_type=AssetType.DOMAIN, name="test-old-wordpress"),
            ],
        )

    def _port_scanner_task_result(self, ports: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "created_at": None,
            "headers": {"receiver": "port_scanner"},
            "payload": {"domain": "example.com", "last_domain": "example.com"},
            "payload_persistent": {"original_domain": "example.com"},
            "result": {"192.0.2.10": ports},
        }

    def test_open_ldap_port_report(self) -> None:
        data = self._port_scanner_task_result(
            {
                "389": {"service": "ldap", "ssl": False, "version": "N/A"},
                "636": {"service": "ldap", "ssl": True, "version": "N/A"},
                "22": {"service": "ssh", "ssl": False, "version": "N/A"},
            }
        )
        reports = reports_from_task_result(data, Language.en_US)  # type: ignore
        self.assertEqual(
            [(report.report_type, report.target) for report in reports],
            [
                (ReportType("open_port_ldap"), "ldap://192.0.2.10:389"),
                (ReportType("open_port_ldap"), "ldap://192.0.2.10:636"),
            ],
        )

        message = self.task_result_to_message(data)
        self.assertIn("The following servers have open LDAP ports", message)
        self.assertIn("ldap://192.0.2.10:389", message)
        self.assertIn("ldap://192.0.2.10:636", message)
        self.assertNotIn("ssh://192.0.2.10:22", message)
