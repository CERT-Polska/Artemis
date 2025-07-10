from test.base import BaseReportingTest

from artemis.modules.webapp_identifier import WebappIdentifier
from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporters import assets_from_task_result


class WebappIdentifierAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = WebappIdentifier  # type: ignore

    def test_reporting(self) -> None:
        data = self.obtain_http_task_result("webapp_identifier", "test-old-wordpress")
        assets = assets_from_task_result(data)
        self.assertEqual(
            set(assets),
            {
                Asset(
                    asset_type=AssetType.TECHNOLOGY,
                    name="http://test-old-wordpress:80/",
                    additional_type="MySQL",
                ),
                Asset(
                    asset_type=AssetType.TECHNOLOGY,
                    name="http://test-old-wordpress:80/",
                    additional_type="Debian",
                ),
                Asset(
                    asset_type=AssetType.TECHNOLOGY,
                    name="http://test-old-wordpress:80/",
                    additional_type="WordPress Site Editor",
                ),
                Asset(
                    asset_type=AssetType.TECHNOLOGY,
                    name="http://test-old-wordpress:80/",
                    additional_type="WordPress Block Editor",
                ),
                Asset(
                    asset_type=AssetType.TECHNOLOGY,
                    name="http://test-old-wordpress:80/",
                    additional_type="PHP",
                    version="7.4.29",
                ),
                Asset(
                    asset_type=AssetType.TECHNOLOGY,
                    name="http://test-old-wordpress:80/",
                    additional_type="Apache HTTP Server",
                    version="2.4.53",
                ),
                Asset(
                    asset_type=AssetType.CMS,
                    name="http://test-old-wordpress:80/",
                    additional_type="wordpress",
                    version="5.9.3",
                ),
            },
        )
