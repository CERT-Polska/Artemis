import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from artemis.config import Config
from artemis.cpe_tools.cpe_main_process import (
    ensure_title_index,
    get_nvd_dir,
    with_version,
)
from artemis.cpe_tools.cpe_utils import (
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


class WithVersionTest(unittest.TestCase):
    """
    A CPE keeps ``*`` in the version slot until someone sets it.
    """

    def test_sets_wildcard_slot(self) -> None:
        self.assertEqual(
            with_version("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "2.4.53"),
            "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*",
        )

    def test_replaces_a_slot_that_already_holds_a_version(self) -> None:
        self.assertEqual(
            with_version("cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*", "2.4.54"),
            "cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*",
        )

    def test_special_values_are_accepted(self) -> None:
        # ``*`` (ANY) and ``-`` (NA) are CPE 2.3 field values, and resetting a dictionary
        # CPE to its versionless family depends on them passing validation.
        cpe = "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*"
        self.assertEqual(with_version(cpe, "*"), "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")
        self.assertEqual(with_version(cpe, "-"), "cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*")

    def test_no_version_returns_unchanged(self) -> None:
        cpe = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
        self.assertEqual(with_version(cpe, None), cpe)
        self.assertEqual(with_version(cpe, ""), cpe)

    def test_invalid_version_leaves_the_slot_alone(self) -> None:
        # A non-version value must not be injected into the CPE; the slot is left as it was
        # so the caller can tell nothing was set.
        cpe = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
        for version in ("latest", "v2.4", "stable", "1.0:extra", " 1.0", "1.0\n"):
            with self.subTest(version=version):
                self.assertEqual(with_version(cpe, version), cpe)

    def test_short_cpe_returns_unchanged(self) -> None:
        # Fewer than six components means there is no version slot to set.
        self.assertEqual(with_version("garbage", "1.0"), "garbage")
        self.assertEqual(with_version("cpe:2.3:a:apache:http_server", "1.0"), "cpe:2.3:a:apache:http_server")

    def test_escaped_colon_in_product_does_not_shift_the_slot(self) -> None:
        # CPE 2.3 escapes a colon inside a field, so a naive split would land on the
        # product's own text instead of the version.
        self.assertEqual(
            with_version("cpe:2.3:a:cgiirc:cgi\\:irc:*:*:*:*:*:*:*:*", "0.5.7"),
            "cpe:2.3:a:cgiirc:cgi\\:irc:0.5.7:*:*:*:*:*:*:*",
        )
        # ... and the same name with a version already in place is replaced, not appended to.
        self.assertEqual(
            with_version("cpe:2.3:a:cgiirc:cgi\\:irc:0.5.7:*:*:*:*:*:*:*", "0.5.9"),
            "cpe:2.3:a:cgiirc:cgi\\:irc:0.5.9:*:*:*:*:*:*:*",
        )


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

    def test_duplicated_title_returns_none(self) -> None:
        # The same title shared by two families is ambiguous, not first-one-seen.
        self.assertIsNone(lookup_cpe("Duplicated Product"))

    def test_title_index_is_keyed_per_product_not_per_release(self) -> None:
        # Asserted on the index itself: lookup_cpe() would also answer these through the
        # token-subset fallback in resolve(), so it cannot tell whether the key still
        # carries a version.
        _make_chunk(
            self.nvd_dir / "nvdcpe-2.0-chunks" / "chunk-00002.json",
            [
                _product("cpe:2.3:a:acme:gizmo:1.0:*:*:*:*:*:*:*", "Acme Gizmo 1.0"),
                _product("cpe:2.3:a:acme:gizmo:2.4.1:*:*:*:*:*:*:*", "Acme Gizmo 2.4.1"),
            ],
        )
        index = ensure_title_index(get_nvd_dir())
        # Two releases, one key, and it is the title with the version cut off.
        self.assertEqual([key for key in index if key.startswith("acme gizmo")], ["acme gizmo"])
        self.assertNotIn("acme gizmo 1 0", index)
        self.assertNotIn("acme gizmo 2 4 1", index)
        # The value is the family CPE, with the version slot wildcarded.
        self.assertEqual(index["acme gizmo"], "cpe:2.3:a:acme:gizmo:*:*:*:*:*:*:*:*")

    def test_version_stripped_from_title_key(self) -> None:
        _make_chunk(
            self.nvd_dir / "nvdcpe-2.0-chunks" / "chunk-00002.json",
            [
                _product(
                    "cpe:2.3:a:joomlaworks:k2:2.8.0:*:*:*:*:joomla\\!:*:*",
                    "JoomlaWorks K2 2.8.0 for Joomla!",
                ),
                _product(
                    "cpe:2.3:a:joomlaworks:k2:2.9.0:*:*:*:*:joomla\\!:*:*",
                    "JoomlaWorks K2 2.9.0 for Joomla!",
                ),
            ],
        )
        # Both releases collapse onto one key holding the version-wildcarded CPE
        # (target_sw is part of the family and is kept).
        self.assertEqual(
            lookup_cpe("JoomlaWorks K2 for Joomla"),
            "cpe:2.3:a:joomlaworks:k2:*:*:*:*:*:joomla\\!:*:*",
        )
        self.assertEqual(
            lookup_cpe("JoomlaWorks K2 for Joomla", version="2.8.0"),
            "cpe:2.3:a:joomlaworks:k2:2.8.0:*:*:*:*:joomla\\!:*:*",
        )

    def test_digits_in_product_name_are_kept(self) -> None:
        # The version comes from the CPE, so digits belonging to the name survive.
        _make_chunk(
            self.nvd_dir / "nvdcpe-2.0-chunks" / "chunk-00002.json",
            [
                _product(
                    "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348:*:*:*:*:*:*:*",
                    "Microsoft Windows Server 2022 10.0.20348",
                ),
            ],
        )
        self.assertEqual(
            lookup_cpe("Microsoft Windows Server 2022"),
            "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*",
        )

    def test_titles_differing_only_by_version_do_not_become_ambiguous(self) -> None:
        # Same family, many releases: still a single unambiguous answer.
        _make_chunk(
            self.nvd_dir / "nvdcpe-2.0-chunks" / "chunk-00002.json",
            [
                _product("cpe:2.3:a:acme:gadget:1.0:*:*:*:*:*:*:*", "Acme Gadget 1.0"),
                _product("cpe:2.3:a:acme:gadget:2.0:*:*:*:*:*:*:*", "Acme Gadget 2.0"),
            ],
        )
        self.assertEqual(
            lookup_cpe("Acme Gadget"),
            "cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*",
        )

    def test_version_stripping_can_make_a_title_ambiguous(self) -> None:
        # "Google Chrome 1.0" and "Google Chrome 1.0" as :a: and :o: share a key once the
        # version is cut off; the lookup reports no match rather than picking one.
        _make_chunk(
            self.nvd_dir / "nvdcpe-2.0-chunks" / "chunk-00002.json",
            [
                _product("cpe:2.3:a:google:chrome:1.0:*:*:*:*:*:*:*", "Google Chrome 1.0"),
                _product("cpe:2.3:o:google:chrome:1.0:*:*:*:*:*:*:*", "Google Chrome 1.0"),
            ],
        )
        self.assertIsNone(lookup_cpe("Google Chrome"))
        # And a query that is only a subset of that title is no less ambiguous.
        self.assertIsNone(lookup_cpe("Chrome"))

    def test_title_naming_a_product_outranks_a_trimmed_one(self) -> None:
        # NVD names the product outright in the versionless entry, so that entry wins over
        # the key left over after trimming a release of a different family.
        _make_chunk(
            self.nvd_dir / "nvdcpe-2.0-chunks" / "chunk-00002.json",
            [
                _product("cpe:2.3:a:acme:relay:1.0:*:*:*:*:*:*:*", "Acme Relay 1.0"),
                _product("cpe:2.3:h:acme:relay:-:*:*:*:*:*:*:*", "Acme Relay"),
                _product("cpe:2.3:o:acme:relay_firmware:2.0:*:*:*:*:*:*:*", "Acme Relay 2.0"),
            ],
        )
        self.assertEqual(
            lookup_cpe("Acme Relay"),
            "cpe:2.3:h:acme:relay:*:*:*:*:*:*:*:*",
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
