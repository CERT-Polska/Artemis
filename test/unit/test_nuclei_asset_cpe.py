import unittest
from typing import Any, Dict, List

from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.modules.nuclei.reporter import NucleiReporter

# An IP is used instead of a domain so that Asset.__post_init__ doesn't perform a DNS lookup.
MATCHED_AT = "http://127.0.0.1:80/wp-login.php"


def _task_result(info: Any) -> Dict[str, Any]:
    """Builds a Nuclei task result containing a single exposed panel finding with a given info section.

    ``info`` is deliberately untyped - the point of some of the tests below is to pass something else
    than the mapping Nuclei is supposed to return.
    """
    finding: Dict[str, Any] = {
        "template": "http/exposed-panels/wordpress-login.yaml",
        "template-id": "wordpress-login",
        "matched-at": MATCHED_AT,
    }
    if info is not None:
        finding["info"] = info

    return {
        "headers": {"receiver": "nuclei"},
        "created_at": None,
        "payload": {},
        "result": [finding],
    }


def _assets(info: Any) -> List[Asset]:
    return NucleiReporter.get_assets(_task_result(info))


class NucleiAssetCPETest(unittest.TestCase):
    def test_cpe_is_taken_from_template_classification(self) -> None:
        (asset,) = _assets(
            {
                "severity": "info",
                "classification": {
                    "cvss-metrics": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    "cwe-id": "CWE-200",
                    "cpe": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
                },
            }
        )

        self.assertEqual(asset.asset_type, AssetType.EXPOSED_PANEL)
        self.assertEqual(asset.name, MATCHED_AT)
        self.assertEqual(asset.additional_type, "wordpress-login")
        self.assertEqual(asset.cpe, "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*")

    def test_cpe_is_none_if_template_doesnt_provide_it(self) -> None:
        # Not all templates describe a concrete piece of software - e.g. the ones for generic login panels.
        infos: List[Dict[str, Any]] = [
            {"severity": "info"},
            {"severity": "info", "classification": {"cwe-id": "CWE-200"}},
            {"severity": "info", "classification": None},
            # A truthy classification that isn't a mapping at all
            {"severity": "info", "classification": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"},
            {"severity": "info", "classification": ["cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"]},
        ]
        for info in infos:
            with self.subTest(info=info):
                (asset,) = _assets(info)
                self.assertIsNone(asset.cpe)

    def test_malformed_cpe_is_skipped(self) -> None:
        # Custom templates may put anything there - the full matrix of what counts as a CPE name
        # is checked in test_to_cpe.
        (asset,) = _assets({"severity": "info", "classification": {"cpe": "wordpress"}})
        self.assertIsNone(asset.cpe)

    def test_asset_without_usable_info_section(self) -> None:
        infos: List[Any] = [None, "info", []]
        for info in infos:
            with self.subTest(info=info):
                (asset,) = _assets(info)
                self.assertIsNone(asset.cpe)


if __name__ == "__main__":
    unittest.main()
