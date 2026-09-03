import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from artemis.config import Config
from artemis.cpe_tools.cpe_utils import (
    fill_version,
    lookup_cpe,
    lookup_cpe_by_plugin_slug,
    lookup_cpe_by_url,
)
from artemis.reporting.base.cpe import extract_cpe


def _make_chunk(path: Path, products: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump({"products": products}, f)


def _product(
    cpe_name: str,
    title: str,
    refs: list[str] | None = None,
    deprecated: bool = False,
) -> dict[str, Any]:
    cpe: dict[str, Any] = {"cpeName": cpe_name, "titles": [{"title": title, "lang": "en"}]}
    if refs:
        cpe["refs"] = [{"ref": url} for url in refs]
    if deprecated:
        cpe["deprecated"] = True
    return {"cpe": cpe}


class FillVersionTest(unittest.TestCase):
    """
    A stored CPE keeps ``*`` in the version slot by definition; the consumer fills it in
    just before use (e.g. cve_lookup, before querying NVD).
    """

    def test_substitutes_wildcard_slot(self) -> None:
        self.assertEqual(
            fill_version("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "2.4.53"),
            "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*",
        )

    def test_keeps_slot_that_already_holds_a_version(self) -> None:
        cpe = "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*"
        self.assertEqual(fill_version(cpe, "2.4.54"), cpe)

    def test_no_version_returns_unchanged(self) -> None:
        cpe = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
        self.assertEqual(fill_version(cpe, None), cpe)
        self.assertEqual(fill_version(cpe, ""), cpe)

    def test_invalid_version_leaves_wildcard(self) -> None:
        # A non-version value must not be injected into the CPE; the wildcard is kept so
        # the caller can tell nothing concrete was filled in.
        cpe = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
        for version in ("latest", "v2.4", "stable", "1.0:extra", " 1.0", "1.0\n"):
            with self.subTest(version=version):
                self.assertEqual(fill_version(cpe, version), cpe)

    def test_short_cpe_returns_unchanged(self) -> None:
        # Fewer than six components means there is no version slot to fill.
        self.assertEqual(fill_version("garbage", "1.0"), "garbage")
        self.assertEqual(fill_version("cpe:2.3:a:apache:http_server", "1.0"), "cpe:2.3:a:apache:http_server")

    def test_escaped_colon_in_product_does_not_shift_the_slot(self) -> None:
        # CPE 2.3 escapes a colon inside a field, so a naive split would land on the
        # product's own text instead of the version.
        self.assertEqual(
            fill_version("cpe:2.3:a:cgiirc:cgi\\:irc:*:*:*:*:*:*:*:*", "0.5.7"),
            "cpe:2.3:a:cgiirc:cgi\\:irc:0.5.7:*:*:*:*:*:*:*",
        )
        # ... and the same name with a version already in place is left alone.
        cpe = "cpe:2.3:a:cgiirc:cgi\\:irc:0.5.7:*:*:*:*:*:*:*"
        self.assertEqual(fill_version(cpe, "0.5.9"), cpe)


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
            "cpe:2.3:a:dupx:product_x:*:*:*:*:*:*:*:*",
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

    def test_deprecated_cpe_is_filtered(self) -> None:
        _make_chunk(
            self.nvd_dir / "nvdcpe-2.0-chunks" / "chunk-00002.json",
            [
                _product(
                    "cpe:2.3:a:acme:sdp:1.0:*:*:*:*:*:*:*",
                    "Sole Deprecated Product",
                    deprecated=True,
                ),
            ],
        )
        self.assertIsNone(lookup_cpe("Sole Deprecated Product"))

    def test_plugin_slug_lookup(self) -> None:
        _make_chunk(
            self.nvd_dir / "nvdcpe-2.0-chunks" / "chunk-00002.json",
            [
                _product(
                    "cpe:2.3:a:acme:superplugin:1.0:*:*:*:*:*:*:*",
                    "Acme SuperPlugin",
                    refs=["https://wordpress.org/plugins/superplugin/"],
                ),
            ],
        )
        self.assertEqual(
            lookup_cpe_by_plugin_slug("superplugin", cms="wordpress"),
            "cpe:2.3:a:acme:superplugin:*:*:*:*:*:*:*:*",
        )
        # The slug is namespaced by CMS; a bare slug without the right cms misses.
        self.assertIsNone(lookup_cpe_by_plugin_slug("superplugin", cms="joomla"))
        self.assertIsNone(lookup_cpe_by_plugin_slug("nonexistent-plugin", cms="wordpress"))

    def test_sw_edition_stripped(self) -> None:
        _make_chunk(
            self.nvd_dir / "nvdcpe-2.0-chunks" / "chunk-00002.json",
            [
                _product(
                    "cpe:2.3:a:acme:edged:1.0:*:*:*:free:*:*:*",
                    "Acme Edged",
                ),
                _product(
                    "cpe:2.3:a:acme:edged:1.0:*:*:*:paid:*:*:*",
                    "Acme Edged",
                ),
            ],
        )
        self.assertEqual(
            lookup_cpe("Acme Edged"),
            "cpe:2.3:a:acme:edged:*:*:*:*:*:*:*:*",
        )

    def test_url_lookup(self) -> None:
        _make_chunk(
            self.nvd_dir / "nvdcpe-2.0-chunks" / "chunk-00002.json",
            [
                _product(
                    "cpe:2.3:a:acme:urlwidget:1.0:*:*:*:*:*:*:*",
                    "Acme UrlWidget",
                    refs=[
                        "https://Example.com/projects/urlwidget/",
                        "https://wordpress.org/plugins/urlwidget/",
                    ],
                ),
            ],
        )
        # The full ref URL resolves via the url index.
        self.assertEqual(
            lookup_cpe_by_url("https://example.com/projects/urlwidget/"),
            "cpe:2.3:a:acme:urlwidget:*:*:*:*:*:*:*:*",
        )
        # Normalization: scheme/host case and trailing slash are ignored.
        self.assertEqual(
            lookup_cpe_by_url("HTTPS://Example.com/projects/urlwidget"),
            "cpe:2.3:a:acme:urlwidget:*:*:*:*:*:*:*:*",
        )
        # A fragment is stripped before lookup.
        self.assertEqual(
            lookup_cpe_by_url("https://example.com/projects/urlwidget/#readme"),
            "cpe:2.3:a:acme:urlwidget:*:*:*:*:*:*:*:*",
        )
        # A version is substituted into the resolved CPE.
        self.assertEqual(
            lookup_cpe_by_url("https://example.com/projects/urlwidget/", version="2.3"),
            "cpe:2.3:a:acme:urlwidget:2.3:*:*:*:*:*:*:*",
        )
        # Unknown URL misses.
        self.assertIsNone(lookup_cpe_by_url("https://example.com/no-such-thing"))
        # Empty/whitespace input is safe.
        self.assertIsNone(lookup_cpe_by_url(""))
        self.assertIsNone(lookup_cpe_by_url("   "))


if __name__ == "__main__":
    unittest.main()
