from test.base import BaseReportingTest

from artemis.modules.webapp_identifier import WebappIdentifier
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporters import assets_from_task_result


class WebappIdentifierAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = WebappIdentifier  # type: ignore

    def test_reporting(self) -> None:
        data = self.obtain_http_task_result("webapp_identifier", "test-old-wordpress")
        assets = assets_from_task_result(data)
        self.assertEqual(
            {(asset.asset_type, asset.name, asset.additional_type, asset.version, asset.cpe) for asset in assets},
            {
                (
                    AssetType.TECHNOLOGY,
                    "http://test-old-wordpress:80/",
                    "MySQL",
                    None,
                    "cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*",
                ),
                # An operating system, hence the "o" part instead of "a"
                (
                    AssetType.TECHNOLOGY,
                    "http://test-old-wordpress:80/",
                    "Debian",
                    None,
                    "cpe:2.3:o:debian:debian_linux:*:*:*:*:*:*:*:*",
                ),
                # Wappalyzer knows no CPE for these
                (AssetType.TECHNOLOGY, "http://test-old-wordpress:80/", "WordPress Site Editor", None, None),
                (AssetType.TECHNOLOGY, "http://test-old-wordpress:80/", "WordPress Block Editor", None, None),
                (
                    AssetType.TECHNOLOGY,
                    "http://test-old-wordpress:80/",
                    "PHP",
                    "7.4.29",
                    "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
                ),
                (
                    AssetType.TECHNOLOGY,
                    "http://test-old-wordpress:80/",
                    "Apache HTTP Server",
                    "2.4.53",
                    "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                ),
                (
                    AssetType.CMS,
                    "http://test-old-wordpress:80/",
                    "wordpress",
                    "5.9.3",
                    "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
                ),
            },
        )
