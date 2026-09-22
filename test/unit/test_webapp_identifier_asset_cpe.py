import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

from artemis.config import Config
from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.modules.webapp_identifier.reporter import (
    WebappIdentifierReporter,
)
from artemis.web_technology_identification import CPE_MAPPING

# An IP is used instead of a domain so that Asset.__post_init__ doesn't perform a DNS lookup.
TARGET = "http://127.0.0.1:80/"

APACHE_CPE = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
WORDPRESS_CPE = "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"
HIGHCHARTS_CPE = "cpe:2.3:a:highcharts:highcharts:*:*:*:*:*:*:*:*"


def _product(cpe_name: str, title: str) -> Dict[str, Any]:
    return {"cpe": {"cpeName": cpe_name, "titles": [{"title": title, "lang": "en"}]}}


def _assets(result: Dict[str, Any]) -> List[Asset]:
    return WebappIdentifierReporter.get_assets(
        {
            "headers": {"receiver": "webapp_identifier"},
            "target_string": TARGET,
            "result": result,
        }
    )


class WebappIdentifierAssetCPETest(unittest.TestCase):
    def setUp(self) -> None:
        # A dictionary of our own, so the assertions don't depend on the NVD one having been
        # downloaded, and so "exactly this title" and "only a subset of this title" are both
        # spelled out here instead of being whatever NVD happens to ship today.
        self._tmp = tempfile.TemporaryDirectory()
        nvd_dir = Path(self._tmp.name)
        chunk = nvd_dir / "nvdcpe-2.0-chunks" / "chunk-00001.json"
        chunk.parent.mkdir(parents=True, exist_ok=True)
        with chunk.open("w", encoding="utf-8") as f:
            json.dump(
                {
                    "products": [
                        _product("cpe:2.3:a:highcharts:highcharts:9.0.0:*:*:*:*:*:*:*", "Highcharts"),
                        _product("cpe:2.3:a:apache:rave:0.20:*:*:*:*:*:*:*", "Apache Rave"),
                        _product("cpe:2.3:a:notsentry:sentry:1.0:*:*:*:*:*:*:*", "Sentry"),
                    ]
                },
                f,
            )
        self._patcher = patch.object(Config.CpeDictionary, "CPE_NVD_DIR", str(nvd_dir))
        self._patcher.start()

    def tearDown(self) -> None:
        self._patcher.stop()
        self._tmp.cleanup()

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

    def test_technology_titled_by_the_dictionary_gets_its_cpe(self) -> None:
        # Wappalyzer knows no CPE for Highcharts; the dictionary titles it exactly, so the asset
        # is named after all. The version stays out of the CPE, as it does for Wappalyzer's own.
        (asset,) = _assets({"technologies": [{"name": "Highcharts", "version": "9.0.0", "cpe": ""}]})

        self.assertEqual(asset.additional_type, "Highcharts")
        self.assertEqual(asset.version, "9.0.0")
        self.assertEqual(asset.cpe, HIGHCHARTS_CPE)

    def test_technology_only_a_token_subset_matches_stays_without_a_cpe(self) -> None:
        # "The Rave" is a subset of the "Apache Rave" title, which is what lookup_cpe()'s token
        # fallback answers with - a different product, whose CVEs would then be reported here.
        # Only an exact title counts, so this one keeps no CPE.
        (asset,) = _assets({"technologies": [{"name": "The Rave", "version": "", "cpe": ""}]})

        self.assertEqual(asset.additional_type, "The Rave")
        self.assertIsNone(asset.cpe)

    def test_cpe_recorded_by_the_scan_outranks_the_dictionary(self) -> None:
        # CPE_MAPPING fills the CPE in at scan time for the handful of technologies whose CPE we
        # know by hand; the dictionary titles this one too, and must not overwrite it.
        (asset,) = _assets({"technologies": [{"name": "Sentry", "version": "", "cpe": CPE_MAPPING["Sentry"]}]})

        self.assertEqual(asset.cpe, CPE_MAPPING["Sentry"])

    def test_legacy_task_results_still_work(self) -> None:
        # Task results saved before the technologies field was introduced have only the tag strings,
        # which carry no CPE - such assets must still be created, with whatever CPE the dictionary
        # knows them under and none when it doesn't know them at all.
        assets = _assets({"technology_tags": ["Apache HTTP Server:2.4.53", "MySQL", "Highcharts:9.0.0"]})

        self.assertEqual(
            [(asset.additional_type, asset.version, asset.cpe) for asset in assets],
            [
                ("Apache HTTP Server", "2.4.53", None),
                ("MySQL", None, None),
                ("Highcharts", "9.0.0", HIGHCHARTS_CPE),
            ],
        )


if __name__ == "__main__":
    unittest.main()
