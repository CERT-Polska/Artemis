from test.base import BaseReportingTest

from artemis.binds import WebApplication
from artemis.modules.webapp_identifier import WebappIdentifier
from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporters import assets_from_task_result


class WebappIdentifierAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = WebappIdentifier  # type: ignore

    def test_reporting(self) -> None:
        data = self.obtain_http_task_result("webapp_identifier", "http://test-old-wordpress:80/")
        message = self.task_result_to_message(data)
        assets = assets_from_task_result(data)
        print(assets)
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
