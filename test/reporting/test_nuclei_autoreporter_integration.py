from test.base import BaseReportingTest

from artemis.modules.nuclei import Nuclei
from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporters import assets_from_task_result


class NucleiAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = Nuclei  # type: ignore

    def test_reporting(self) -> None:
        data = self.obtain_http_task_result("nuclei", "test-phpmyadmin-easy-password")
        message = self.task_result_to_message(data)
        self.assertIn(
            "The following addresses contain login panels, analytics services, management panels etc.", message
        )
        self.assertIn("http://test-phpmyadmin-easy-password:80: phpMyAdmin panel was detected.", message)

    def test_asset_discovery(self) -> None:
        data = self.obtain_http_task_result("nuclei", "test-old-wordpress")
        message = self.task_result_to_message(data)
        # this should not be reported as WordPress panel detection template is skipped from reporting (but not from running)
        self.assertNotIn("test-old-wordpress", message)
        assets = assets_from_task_result(data)
        self.assertEqual(
            assets,
            [
                Asset(
                    asset_type=AssetType.EXPOSED_PANEL,
                    name="http://test-old-wordpress:80/wp-login.php",
                    additional_type="wordpress-login",
                    original_karton_name=None,
                    last_domain=None,
                )
            ],
        )
