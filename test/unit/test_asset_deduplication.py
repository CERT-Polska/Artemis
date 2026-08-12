import unittest
from typing import Any, Dict, List, Optional

from artemis.binds import Service, TaskType, WebApplication
from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.language import Language
from artemis.reporting.export.db import DataLoader

# An IP is used instead of a domain so that Asset.__post_init__ doesn't perform a DNS lookup.
HOST = "127.0.0.1"
URL = "http://127.0.0.1:80/"
WORDPRESS_CPE = "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"


class _DBWithTaskResults:
    """Just enough of DB for DataLoader: the task results it should load."""

    def __init__(self, task_results: List[Dict[str, Any]]) -> None:
        self._task_results = task_results

    def get_task_results_since(self, time_from: Any, tag: Optional[str] = None) -> List[Dict[str, Any]]:
        return self._task_results


def _webapp_identifier_result(version: Optional[str], cpe: Optional[str]) -> Dict[str, Any]:
    return {
        "id": "webapp-identifier-result",
        "analysis_id": "analysis",
        "status": "OK",
        "target_string": URL,
        "created_at": None,
        "task": {
            "headers": {"receiver": "webapp_identifier", "type": TaskType.SERVICE, "service": Service.HTTP},
            "payload": {"host": HOST, "port": 80, "last_domain": HOST},
            "payload_persistent": {"original_domain": HOST},
        },
        "result": {"technologies": [{"name": "WordPress", "version": version, "cpe": cpe}]},
    }


def _wp_scanner_result(version: Optional[str]) -> Dict[str, Any]:
    return {
        "id": "wp-scanner-result",
        "analysis_id": "analysis",
        "status": "OK",
        "target_string": URL,
        "created_at": None,
        "task": {
            "headers": {"receiver": "wp_scanner", "type": TaskType.WEBAPP, "webapp": WebApplication.WORDPRESS},
            "payload": {"url": URL, "last_domain": HOST},
            "payload_persistent": {"original_domain": HOST},
        },
        # wp_scanner saves the key only when it managed to read the version.
        "result": {"wp_version": version} if version else {},
    }


def _cms_asset(task_results: List[Dict[str, Any]]) -> Asset:
    assets = DataLoader(
        db=_DBWithTaskResults(task_results),  # type: ignore[arg-type]
        blocklist=[],
        # Language is built with the functional Enum API from languages.txt, so mypy can't see its members
        # - hence the ignore, the same one every other use of Language.en_US in the codebase carries.
        language=Language.en_US,  # type: ignore[attr-defined]
        tag=None,
        silent=True,
    ).assets
    (asset,) = [asset for asset in assets if asset.asset_type == AssetType.CMS]
    return asset


class AssetDeduplicationTest(unittest.TestCase):
    def test_the_two_descriptions_of_one_cms_are_merged(self) -> None:
        # Both modules describe the same WordPress on the same URL, so they produce the same deduplication
        # key, but only webapp_identifier knows a CPE, and here only wp_scanner determined the version.
        # Whichever of them is loaded first, the exported asset has to carry both.
        for order in ("wp_scanner first", "webapp_identifier first"):
            with self.subTest(order=order):
                task_results = [
                    _wp_scanner_result(version="5.9.3"),
                    _webapp_identifier_result(version=None, cpe=WORDPRESS_CPE),
                ]
                if order == "webapp_identifier first":
                    task_results.reverse()

                asset = _cms_asset(task_results)

                self.assertEqual(asset.additional_type, "wordpress")
                self.assertEqual(asset.version, "5.9.3")
                self.assertEqual(asset.cpe, WORDPRESS_CPE)

    def test_a_known_value_is_not_overwritten(self) -> None:
        asset = _cms_asset(
            [
                _webapp_identifier_result(version="5.9.3", cpe=WORDPRESS_CPE),
                _wp_scanner_result(version="5.9.4"),
            ]
        )

        self.assertEqual(asset.version, "5.9.3")
        self.assertEqual(asset.cpe, WORDPRESS_CPE)

    def test_a_single_description_is_left_alone(self) -> None:
        asset = _cms_asset([_wp_scanner_result(version="5.9.3")])

        self.assertEqual(asset.version, "5.9.3")
        self.assertIsNone(asset.cpe)


if __name__ == "__main__":
    unittest.main()
