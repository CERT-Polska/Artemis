from test.base import BaseReportingTest

from artemis.binds import WebApplication
from artemis.modules.joomla_scanner import JoomlaScanner
from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporters import assets_from_task_result


class JoomlaScannerAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = JoomlaScanner  # type: ignore

    def test_reporting(self) -> None:
        data = self.obtain_webapp_task_result("joomla_scanner", WebApplication.JOOMLA, "http://test-old-joomla:80/")
        message = self.task_result_to_message(data)
        self.assertIn("The following addresses contain old Joomla", message)
        self.assertIn("http://test-old-joomla:80/ - Joomla 4.0.5", message)

    def test_asset_discovery(self) -> None:
        data = self.obtain_webapp_task_result("joomla_scanner", WebApplication.JOOMLA, "http://test-old-joomla:80/")
        assets = assets_from_task_result(data)
        self.assertEqual(
            assets,
            [
                Asset(
                    asset_type=AssetType.CMS,
                    name="http://test-old-joomla:80/",
                    additional_type="joomla",
                    version="4.0.5",
                    original_karton_name=None,
                    last_domain=None,
                )
            ],
        )
