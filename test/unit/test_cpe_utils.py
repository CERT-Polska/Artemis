import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from artemis.config import Config
from artemis.cpe_tools.cpe_utils import lookup_cpe
from artemis.reporting.base.cpe import extract_cpe


def _make_chunk(path: Path, products: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump({"products": products}, f)


def _product(cpe_name: str, title: str) -> dict[str, Any]:
    return {"cpe": {"cpeName": cpe_name, "titles": [{"title": title, "lang": "en"}]}}


class CpeUtilsTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.nvd_dir = Path(self._tmp.name)
        _make_chunk(
            self.nvd_dir / "nvdcpe-2.0-chunks" / "chunk-00001.json",
            [
                _product(
                    "cpe:2.3:a:cisco:anyconnect_secure_mobility_client:4.9:*:*:*:*:*:*:*",
                    "Cisco AnyConnect Secure Mobility Client",
                ),
                _product("cpe:2.3:a:ivanti:connect_secure:9.1:*:*:*:*:*:*:*", "Ivanti Connect Secure"),
                _product(
                    "cpe:2.3:a:pulsesecure:pulse_connect_secure:9.1:*:*:*:*:*:*:*",
                    "Pulse Connect Secure",
                ),
                _product("cpe:2.3:a:fortinet:fortigate:7.0:*:*:*:*:*:*:*", "Fortinet FortiGate"),
                _product("cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*", "Acme Widget"),
                _product("cpe:2.3:a:beta:widget:1.0:*:*:*:*:*:*:*", "Beta Widget"),
                _product("cpe:2.3:a:dupx:product_x:1.0:*:*:*:*:*:*:*", "Duplicated Product"),
                _product("cpe:2.3:a:dupy:product_y:1.0:*:*:*:*:*:*:*", "Duplicated Product"),
            ],
        )
        self._patcher = patch.object(Config.CpeDictionary, "CPE_NVD_DIR", str(self.nvd_dir))
        self._patcher.start()

    def tearDown(self) -> None:
        self._patcher.stop()
        self._tmp.cleanup()

    def test_exact_title_match(self) -> None:
        self.assertEqual(
            lookup_cpe("Ivanti Connect Secure"),
            "cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*",
        )

    def test_token_subset_match(self) -> None:
        self.assertEqual(
            lookup_cpe("Cisco AnyConnect"),
            "cpe:2.3:a:cisco:anyconnect_secure_mobility_client:*:*:*:*:*:*:*:*",
        )

    def test_normalizes_case_and_whitespace(self) -> None:
        self.assertEqual(
            lookup_cpe("  cisco  ANYCONNECT "),
            "cpe:2.3:a:cisco:anyconnect_secure_mobility_client:*:*:*:*:*:*:*:*",
        )

    def test_version_substitution(self) -> None:
        self.assertEqual(
            lookup_cpe("Ivanti Connect Secure", version="9.1"),
            "cpe:2.3:a:ivanti:connect_secure:9.1:*:*:*:*:*:*:*",
        )

    def test_ambiguous_query_returns_none(self) -> None:
        # "Widget" matches two different vendor:product families.
        self.assertIsNone(lookup_cpe("Widget"))

    def test_duplicated_title_picks_first(self) -> None:
        # The same title shared by two families resolves to the first one seen.
        self.assertEqual(
            lookup_cpe("Duplicated Product"),
            "cpe:2.3:a:dupx:product_x:*:*:*:*:*:*:*",
        )

    def test_unknown_product_returns_none(self) -> None:
        self.assertIsNone(lookup_cpe("Totally Unknown Product"))

    def test_empty_and_stopword_only_input(self) -> None:
        self.assertIsNone(lookup_cpe(""))
        self.assertIsNone(lookup_cpe("   "))
        self.assertIsNone(lookup_cpe("the and of"))  # only stopwords -> no tokens

    def test_result_is_a_valid_cpe(self) -> None:
        cpe = lookup_cpe("Cisco AnyConnect")
        self.assertIsNotNone(cpe)
        assert cpe is not None
        self.assertEqual(extract_cpe(cpe), cpe)

    def test_missing_dictionary_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as empty:
            with patch.object(Config.CpeDictionary, "CPE_NVD_DIR", empty):
                self.assertIsNone(lookup_cpe("Cisco AnyConnect"))


if __name__ == "__main__":
    unittest.main()
