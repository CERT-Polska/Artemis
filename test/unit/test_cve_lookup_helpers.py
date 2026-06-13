import unittest
from typing import Any, Dict

from artemis.modules.cve_lookup import (
    _cpe_product_key,
    _extract_cves,
    _fill_cpe_version,
    _is_product_vulnerable,
)


class FillCpeVersionTest(unittest.TestCase):
    def test_substitutes_wildcard_slot(self) -> None:
        cpe = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
        self.assertEqual(
            _fill_cpe_version(cpe, "2.4.53"),
            "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*",
        )

    def test_keeps_real_version(self) -> None:
        cpe = "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*"
        self.assertEqual(_fill_cpe_version(cpe, "2.4.54"), cpe)

    def test_no_version_returns_unchanged(self) -> None:
        cpe = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
        self.assertEqual(_fill_cpe_version(cpe, None), cpe)

    def test_malformed_cpe_returns_unchanged(self) -> None:
        self.assertEqual(_fill_cpe_version("garbage", "1.0"), "garbage")


class ExtractCvesTest(unittest.TestCase):
    def test_empty_vulnerabilities(self) -> None:
        self.assertEqual(_extract_cves({"vulnerabilities": []}), [])

    def test_extracts_id_description_and_cvss(self) -> None:
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-1234",
                        "descriptions": [
                            {"lang": "es", "value": "ignored"},
                            {"lang": "en", "value": "example vulnerability"},
                        ],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]},
                    }
                }
            ]
        }
        self.assertEqual(
            _extract_cves(payload),
            [{"id": "CVE-2024-1234", "description": "example vulnerability", "cvss_score": 7.5}],
        )

    def test_falls_back_through_cvss_versions(self) -> None:
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-OLD",
                        "descriptions": [],
                        "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 4.0}}]},
                    }
                }
            ]
        }
        self.assertEqual(_extract_cves(payload)[0]["cvss_score"], 4.0)

    def test_no_metrics_yields_none_score(self) -> None:
        payload = {"vulnerabilities": [{"cve": {"id": "CVE-X", "descriptions": []}}]}
        self.assertEqual(_extract_cves(payload), [{"id": "CVE-X", "description": "", "cvss_score": None}])

    def test_ignores_non_dict_entries(self) -> None:
        payload = {"vulnerabilities": ["bad", None, {"cve": {"id": "OK", "descriptions": []}}]}
        self.assertEqual(
            _extract_cves(payload),
            [{"id": "OK", "description": "", "cvss_score": None}],
        )

    def test_rejects_non_dict_payload(self) -> None:
        self.assertEqual(_extract_cves(["nope"]), [])

    def test_rejects_missing_vulnerabilities_key(self) -> None:
        self.assertEqual(_extract_cves({}), [])

    def test_filters_to_vulnerable_product(self) -> None:
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-REAL",
                        "descriptions": [],
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                },
                {
                    "cve": {
                        "id": "CVE-RUNS-ON",
                        "descriptions": [],
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {"vulnerable": True, "criteria": "cpe:2.3:a:other:product:*:*:*:*:*:*:*:*"},
                                            {
                                                "vulnerable": False,
                                                "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                                            },
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                },
            ]
        }
        ids = [c["id"] for c in _extract_cves(payload, "a:apache:http_server")]
        self.assertEqual(ids, ["CVE-REAL"])


class CpeProductKeyTest(unittest.TestCase):
    def test_extracts_part_vendor_product(self) -> None:
        self.assertEqual(
            _cpe_product_key("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"),
            "a:apache:http_server",
        )

    def test_short_cpe_returns_empty(self) -> None:
        self.assertEqual(_cpe_product_key("garbage"), "")


class IsProductVulnerableTest(unittest.TestCase):
    @staticmethod
    def _cve(*matches: Dict[str, Any]) -> Dict[str, Any]:
        return {"configurations": [{"nodes": [{"cpeMatch": list(matches)}]}]}

    def test_true_when_product_is_vulnerable(self) -> None:
        cve = self._cve({"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"})
        self.assertTrue(_is_product_vulnerable(cve, "a:apache:http_server"))

    def test_false_when_product_only_runs_on(self) -> None:
        cve = self._cve(
            {"vulnerable": True, "criteria": "cpe:2.3:a:other:module:*:*:*:*:*:*:*:*"},
            {"vulnerable": False, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"},
        )
        self.assertFalse(_is_product_vulnerable(cve, "a:apache:http_server"))

    def test_false_when_no_configurations(self) -> None:
        self.assertFalse(_is_product_vulnerable({}, "a:apache:http_server"))
