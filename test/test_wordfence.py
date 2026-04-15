import unittest
from typing import Any, Dict
from unittest.mock import MagicMock, patch

from artemis.wordfence import _is_version_in_range, get_vulnerabilities_for_plugin


class TestIsVersionInRange(unittest.TestCase):
    def _range(
        self, from_ver: str, to_ver: str, from_inclusive: bool = True, to_inclusive: bool = True
    ) -> Dict[str, Any]:
        return {
            f"{from_ver} - {to_ver}": {
                "from_version": from_ver,
                "to_version": to_ver,
                "from_inclusive": from_inclusive,
                "to_inclusive": to_inclusive,
            }
        }

    def test_version_within_inclusive_range(self) -> None:
        self.assertTrue(_is_version_in_range("2.1.0", self._range("1.0.0", "2.1.3")))

    def test_version_at_upper_inclusive_bound(self) -> None:
        self.assertTrue(_is_version_in_range("2.1.3", self._range("1.0.0", "2.1.3")))

    def test_version_above_upper_inclusive_bound(self) -> None:
        self.assertFalse(_is_version_in_range("2.1.4", self._range("1.0.0", "2.1.3")))

    def test_version_at_upper_exclusive_bound(self) -> None:
        self.assertFalse(_is_version_in_range("2.1.3", self._range("1.0.0", "2.1.3", to_inclusive=False)))

    def test_version_just_below_upper_exclusive_bound(self) -> None:
        self.assertTrue(_is_version_in_range("2.1.2", self._range("1.0.0", "2.1.3", to_inclusive=False)))

    def test_version_at_lower_inclusive_bound(self) -> None:
        self.assertTrue(_is_version_in_range("1.0.0", self._range("1.0.0", "2.1.3")))

    def test_version_below_lower_bound(self) -> None:
        self.assertFalse(_is_version_in_range("0.9.9", self._range("1.0.0", "2.1.3")))

    def test_wildcard_from_version(self) -> None:
        self.assertTrue(_is_version_in_range("0.1.0", self._range("*", "2.1.3")))

    def test_wildcard_to_version(self) -> None:
        self.assertTrue(_is_version_in_range("99.0.0", self._range("1.0.0", "*")))

    def test_both_wildcards(self) -> None:
        self.assertTrue(_is_version_in_range("5.0.0", self._range("*", "*")))

    def test_invalid_version_string(self) -> None:
        self.assertFalse(_is_version_in_range("not-a-version", self._range("1.0.0", "2.0.0")))

    def test_multiple_ranges_first_matches(self) -> None:
        ranges = {
            "1.0.0 - 1.5.0": {
                "from_version": "1.0.0",
                "to_version": "1.5.0",
                "from_inclusive": True,
                "to_inclusive": True,
            },
            "2.0.0 - 2.5.0": {
                "from_version": "2.0.0",
                "to_version": "2.5.0",
                "from_inclusive": True,
                "to_inclusive": True,
            },
        }
        self.assertTrue(_is_version_in_range("1.3.0", ranges))
        self.assertTrue(_is_version_in_range("2.3.0", ranges))
        self.assertFalse(_is_version_in_range("1.9.0", ranges))


class TestGetVulnerabilitiesForPlugin(unittest.TestCase):
    SAMPLE_FEED = {
        "uuid-1111": {
            "id": "uuid-1111",
            "title": "XSS in contact-form-7",
            "cve": "CVE-2023-1234",
            "cvss_v3": {"score": 7.5},
            "patched_versions": ["5.8.0"],
            "software": [
                {
                    "slug": "contact-form-7",
                    "affected_versions": {
                        "* - 5.7.9": {
                            "from_version": "*",
                            "to_version": "5.7.9",
                            "from_inclusive": True,
                            "to_inclusive": True,
                        }
                    },
                }
            ],
        },
        "uuid-2222": {
            "id": "uuid-2222",
            "title": "SQLi in other-plugin",
            "cve": "CVE-2023-9999",
            "cvss_v3": {"score": 9.8},
            "patched_versions": ["3.0.0"],
            "software": [
                {
                    "slug": "other-plugin",
                    "affected_versions": {
                        "* - 2.9.9": {
                            "from_version": "*",
                            "to_version": "2.9.9",
                            "from_inclusive": True,
                            "to_inclusive": True,
                        }
                    },
                }
            ],
        },
    }

    def _mock_response(self) -> MagicMock:
        mock = MagicMock()
        mock.json.return_value = self.SAMPLE_FEED
        return mock

    @patch("artemis.wordfence.FallbackAPICache.get")
    def test_returns_matching_vulnerability(self, mock_get: MagicMock) -> None:
        mock_get.return_value = self._mock_response()

        # reset in-memory index between tests
        import artemis.wordfence as wf

        wf._WORDFENCE_INDEX = None

        results = get_vulnerabilities_for_plugin("contact-form-7", "5.7.1")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["cve"], "CVE-2023-1234")
        self.assertAlmostEqual(results[0]["cvss"], 7.5)
        self.assertEqual(results[0]["patched_versions"], ["5.8.0"])

    @patch("artemis.wordfence.FallbackAPICache.get")
    def test_no_match_for_patched_version(self, mock_get: MagicMock) -> None:
        mock_get.return_value = self._mock_response()

        import artemis.wordfence as wf

        wf._WORDFENCE_INDEX = None

        results = get_vulnerabilities_for_plugin("contact-form-7", "5.8.0")
        self.assertEqual(results, [])

    @patch("artemis.wordfence.FallbackAPICache.get")
    def test_no_match_for_unknown_plugin(self, mock_get: MagicMock) -> None:
        mock_get.return_value = self._mock_response()

        import artemis.wordfence as wf

        wf._WORDFENCE_INDEX = None

        results = get_vulnerabilities_for_plugin("unknown-plugin", "1.0.0")
        self.assertEqual(results, [])

    @patch("artemis.wordfence.FallbackAPICache.get")
    def test_no_request_when_index_cached(self, mock_get: MagicMock) -> None:
        mock_get.return_value = self._mock_response()

        import artemis.wordfence as wf

        wf._WORDFENCE_INDEX = None

        get_vulnerabilities_for_plugin("contact-form-7", "5.7.1")
        get_vulnerabilities_for_plugin("contact-form-7", "5.7.1")

        # Feed should be fetched only once despite two calls
        mock_get.assert_called_once()


if __name__ == "__main__":
    unittest.main()
