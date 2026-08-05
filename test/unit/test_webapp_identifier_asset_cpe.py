import unittest
from typing import Any, Dict, List

from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.modules.webapp_identifier.reporter import (
    WebappIdentifierReporter,
)

# An IP is used instead of a domain so that Asset.__post_init__ doesn't perform a DNS lookup.
TARGET = "http://127.0.0.1:80/"

APACHE_CPE = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
WORDPRESS_CPE = "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"


def _assets(result: Dict[str, Any]) -> List[Asset]:
    return WebappIdentifierReporter.get_assets(
        {
            "headers": {"receiver": "webapp_identifier"},
            "target_string": TARGET,
            "result": result,
        }
    )


class WebappIdentifierAssetCPETest(unittest.TestCase):
    def test_cpe_is_taken_from_detected_technologies(self) -> None:
        technology, cms = _assets(
            {
                "webapp": "unknown",
                "technologies": [
                    {"name": "Apache HTTP Server", "version": "2.4.53", "cpe": APACHE_CPE},
                    {"name": "WordPress", "version": "5.9.3", "cpe": WORDPRESS_CPE},
                ],
            }
        )

        self.assertEqual(technology.asset_type, AssetType.TECHNOLOGY)
        self.assertEqual(technology.additional_type, "Apache HTTP Server")
        # The version is kept apart from the CPE - Wappalyzer leaves the CPE version slot wildcarded.
        self.assertEqual(technology.version, "2.4.53")
        self.assertEqual(technology.cpe, APACHE_CPE)

        self.assertEqual(cms.asset_type, AssetType.CMS)
        self.assertEqual(cms.additional_type, "wordpress")
        self.assertEqual(cms.version, "5.9.3")
        self.assertEqual(cms.cpe, WORDPRESS_CPE)

    def test_cpe_is_none_if_wappalyzer_doesnt_provide_it(self) -> None:
        # Wappalyzer knows no CPE for some technologies - then it returns an empty string.
        (asset,) = _assets({"technologies": [{"name": "WordPress Site Editor", "version": "", "cpe": ""}]})

        self.assertEqual(asset.additional_type, "WordPress Site Editor")
        self.assertIsNone(asset.version)
        self.assertIsNone(asset.cpe)

    def test_malformed_cpe_is_skipped(self) -> None:
        # The same validation as on the Nuclei side - the technologies come from a task result, which
        # may have been saved by an older (or patched) version of the module.
        (asset,) = _assets({"technologies": [{"name": "Apache HTTP Server", "cpe": "apache:http_server"}]})
        self.assertIsNone(asset.cpe)

    def test_legacy_task_results_still_work(self) -> None:
        # Task results saved before the technologies field was introduced have only the tag strings,
        # which carry no CPE - such assets must still be created, just without it.
        assets = _assets({"technology_tags": ["Apache HTTP Server:2.4.53", "MySQL"]})

        self.assertEqual(
            [(asset.additional_type, asset.version, asset.cpe) for asset in assets],
            [("Apache HTTP Server", "2.4.53", None), ("MySQL", None, None)],
        )


if __name__ == "__main__":
    unittest.main()
