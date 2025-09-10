from test.base import BaseReportingTest

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
                )
            ],
        )
