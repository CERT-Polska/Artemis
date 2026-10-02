import socket
from test.base import BaseReportingTest
from unittest.mock import patch

from artemis.modules.port_scanner import PortScanner
from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporters import assets_from_task_result


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

    def test_open_ldap_port_report(self) -> None:
        with patch("artemis.modules.port_scanner.PORTS", [389, 636]):
            data = self.obtain_domain_task_result("port_scanner", "test-openldap")
        ip = socket.gethostbyname("test-openldap")

        message = self.task_result_to_message(data)
        self.assertIn("The following servers have open LDAP ports", message)
        self.assertIn(f"ldap://{ip}:389", message)
        self.assertIn(f"ldap://{ip}:636", message)
