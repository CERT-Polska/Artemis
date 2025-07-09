from test.base import BaseReportingTest

from artemis.binds import WebApplication
from artemis.modules.wp_scanner import WordPressScanner
from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporters import assets_from_task_result


class WPScannerAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = WordPressScanner  # type: ignore

    def test_reporting(self) -> None:
        data = self.obtain_webapp_task_result("wp_scanner", WebApplication.WORDPRESS, "http://test-old-wordpress:80/")
        message = self.task_result_to_message(data)
        self.assertIn("The following addresses contain WordPress versions that are no longer", message)
        self.assertIn("http://test-old-wordpress:80/ - WordPress 5.9.3", message)

    def test_asset_discovery(self) -> None:
        data = self.obtain_webapp_task_result("wp_scanner", WebApplication.WORDPRESS, "http://test-old-wordpress:80/")
        assets = assets_from_task_result(data)
        self.assertEqual(
            assets,
            [
                Asset(
                    asset_type=AssetType.CMS,
                    name="http://test-old-wordpress:80/",
                    additional_type="wordpress",
                    version="5.9.3",
                    original_karton_name=None,
                    last_domain=None,
                )
            ],
        )
