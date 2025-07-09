from test.base import BaseReportingTest
from typing import Any, Dict

from karton.core import Task

from artemis.binds import Service, TaskType
from artemis.modules.wp_scanner import WPScanner
from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.language import Language
from artemis.reporting.base.reporters import (
    assets_from_task_result,
    reports_from_task_result,
)


class WPScannerAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = WPScanner  # type: ignore

    def test_reporting(self) -> None:
        data = self.obtain_task_result("wp_scanner", "test-old-wordpress")
        message = self.task_result_to_message(data)
        self.assertIn(
            "The following addresses contain WordPress versions that are no longer", message
        )
        self.assertIn("http://test-old-wordpress:80: WordPress 5.9.3", message)

    def test_asset_discovery(self) -> None:
        data = self.obtain_task_result("wp_scanner", "test-old-wordpress")
        message = self.task_result_to_message(data)
        assets = assets_from_task_result(data)
        self.assertEqual(
            assets,
            [
                Asset(
                    asset_type=AssetType.CMS,
                    name="http://test-old-wordpress:80/",
                    additional_type="wordpress",
                    original_karton_name=None,
                    last_domain=None,
                )
            ],
        )
