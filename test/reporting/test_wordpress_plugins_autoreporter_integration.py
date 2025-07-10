from test.base import BaseReportingTest

from artemis.binds import WebApplication
from artemis.modules.wordpress_plugins import WordpressPlugins
from artemis.reporting.base.reporters import assets_from_task_result


class WPScannerAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = WordpressPlugins  # type: ignore

    def test_reporting(self) -> None:
        data = self.obtain_webapp_task_result(
            "wordpress_plugins", WebApplication.WORDPRESS, "http://test-old-wordpress:80/"
        )
        message = self.task_result_to_message(data)
        print(message)

    def test_asset_discovery(self) -> None:
        data = self.obtain_webapp_task_result(
            "wordpress_plugins", WebApplication.WORDPRESS, "http://test-old-wordpress:80/"
        )
        assets = assets_from_task_result(data)
        print(assets)
