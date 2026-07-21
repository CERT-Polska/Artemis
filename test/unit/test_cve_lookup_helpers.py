import unittest
from typing import Any, Dict, List

from artemis.modules.cve_lookup import (
    _best_base_score,
    _cpe_product_key,
    _extract_cves,
    _fill_cpe_version,
    _has_concrete_version,
    _is_product_vulnerable,
)


class HasConcreteVersionTest(unittest.TestCase):
    """
    NVD answers a wildcard-version ``cpeName`` with HTTP 404 (verified against apache,
    wordpress and nginx), so these CPEs must never reach the API.
    """

    def test_true_for_real_version(self) -> None:
        self.assertTrue(_has_concrete_version("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"))

    def test_false_for_wildcard_version(self) -> None:
        self.assertFalse(_has_concrete_version("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"))

    def test_false_for_empty_or_dash_version(self) -> None:
        self.assertFalse(_has_concrete_version("cpe:2.3:a:apache:http_server::*:*:*:*:*:*:*"))
        self.assertFalse(_has_concrete_version("cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*"))

    def test_false_for_truncated_cpe(self) -> None:
        self.assertFalse(_has_concrete_version("cpe:2.3:a:apache"))


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

    def test_junk_version_leaves_wildcard(self) -> None:
        # A non-version value (e.g. "latest") must not be injected into the CPE; the
        # wildcard is kept so NVD still range-matches the product.
        cpe = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
        self.assertEqual(_fill_cpe_version(cpe, "latest"), cpe)


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

    def test_reads_cvss_v4(self) -> None:
        # A CVE that only publishes CVSS v4 must still yield its base score.
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-V4-ONLY",
                        "descriptions": [],
                        "metrics": {"cvssMetricV40": [{"type": "Primary", "cvssData": {"baseScore": 9.3}}]},
                    }
                }
            ]
        }
        self.assertEqual(_extract_cves(payload)[0]["cvss_score"], 9.3)

    def test_prefers_primary_over_higher_secondary(self) -> None:
        # NVD's own Primary score wins even when a CNA-supplied Secondary score is higher.
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-MULTI",
                        "descriptions": [],
                        "metrics": {
                            "cvssMetricV31": [
                                {"type": "Secondary", "cvssData": {"baseScore": 9.8}},
                                {"type": "Primary", "cvssData": {"baseScore": 7.5}},
                            ]
                        },
                    }
                }
            ]
        }
        self.assertEqual(_extract_cves(payload)[0]["cvss_score"], 7.5)

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

    def test_false_when_node_is_negated(self) -> None:
        # A negated node matches the *absence* of its CPEs, so our product appearing
        # there does not make it the vulnerable component.
        cve = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "negate": True,
                            "cpeMatch": [
                                {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
                            ],
                        }
                    ]
                }
            ]
        }
        self.assertFalse(_is_product_vulnerable(cve, "a:apache:http_server"))

    def test_false_when_configuration_is_negated(self) -> None:
        cve = {
            "configurations": [
                {
                    "negate": True,
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
                            ]
                        }
                    ],
                }
            ]
        }
        self.assertFalse(_is_product_vulnerable(cve, "a:apache:http_server"))

    def test_true_across_and_joined_nodes(self) -> None:
        # AND config (CVE-2021-44228 shape): the vulnerable product sits in one node
        # and a vulnerable=false "running on" platform in another. Our product is
        # still the vulnerable component.
        cve = {
            "configurations": [
                {
                    "operator": "AND",
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
                            ],
                        },
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {"vulnerable": False, "criteria": "cpe:2.3:o:vendor:platform:*:*:*:*:*:*:*:*"}
                            ],
                        },
                    ],
                }
            ]
        }
        self.assertTrue(_is_product_vulnerable(cve, "a:apache:http_server"))

    def test_false_when_and_requires_a_second_vulnerable_component(self) -> None:
        # An AND config where *both* nodes name a vulnerable component means the CVE only
        # applies when both are present. Detecting just one of them is not enough - this is
        # the case the earlier operator-blind check reported as a false positive.
        cve = {
            "configurations": [
                {
                    "operator": "AND",
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
                            ],
                        },
                        {
                            "operator": "OR",
                            "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:other:product:*:*:*:*:*:*:*:*"}],
                        },
                    ],
                }
            ]
        }
        self.assertFalse(_is_product_vulnerable(cve, "a:apache:http_server"))

    def test_true_when_or_joins_two_vulnerable_components(self) -> None:
        # The same shape under OR means either component alone is affected, so our product
        # matching one of the nodes is enough.
        cve = {
            "configurations": [
                {
                    "operator": "OR",
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
                            ],
                        },
                        {
                            "operator": "OR",
                            "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:other:product:*:*:*:*:*:*:*:*"}],
                        },
                    ],
                }
            ]
        }
        self.assertTrue(_is_product_vulnerable(cve, "a:apache:http_server"))


class BestBaseScoreTest(unittest.TestCase):
    def test_returns_none_for_non_list(self) -> None:
        self.assertIsNone(_best_base_score(None))
        self.assertIsNone(_best_base_score({}))

    def test_returns_none_when_no_scores(self) -> None:
        self.assertIsNone(_best_base_score([{"type": "Primary", "cvssData": {}}]))

    def test_prefers_primary(self) -> None:
        entries = [
            {"type": "Secondary", "cvssData": {"baseScore": 9.8}},
            {"type": "Primary", "cvssData": {"baseScore": 6.1}},
        ]
        self.assertEqual(_best_base_score(entries), 6.1)

    def test_highest_when_no_primary(self) -> None:
        entries = [
            {"type": "Secondary", "cvssData": {"baseScore": 4.0}},
            {"type": "Secondary", "cvssData": {"baseScore": 8.2}},
        ]
        self.assertEqual(_best_base_score(entries), 8.2)

    def test_ignores_non_dict_and_missing_scores(self) -> None:
        entries: List[Any] = ["bad", None, {"cvssData": {"baseScore": 5.5}}, {"cvssData": {}}]
        self.assertEqual(_best_base_score(entries), 5.5)
