import unittest
from typing import Any, Dict, List, Optional
from unittest.mock import patch

from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.modules.wordpress_plugins.reporter import (
    WordpressPluginsReporter,
)

# An IP is used instead of a domain so that Asset.__post_init__ doesn't perform a DNS lookup.
TARGET = "http://127.0.0.1:80/"

CONTACT_FORM_7_CPE = "cpe:2.3:a:rocklobster:contact_form_7:*:*:*:*:*:wordpress:*:*"

# What artemis.cpe_tools would answer, so these tests don't depend on the NVD dictionary having been
# downloaded - that mapping is built and tested there, this module only has to consult it correctly.
FAKE_INDEX = {"contact-form-7": CONTACT_FORM_7_CPE}


def _fake_lookup(slug: str, cms: str, version: Optional[str] = None) -> Optional[str]:
    assert cms == "wordpress", "a WordPress plugin must be looked up under the WordPress namespace"
    return FAKE_INDEX.get(slug.strip().lower())


def _assets(plugins: Dict[str, Any]) -> List[Asset]:
    return WordpressPluginsReporter.get_assets(
        {
            "headers": {"receiver": "wordpress_plugins", "type": "webapp", "webapp": "wordpress"},
            "payload": {"url": TARGET},
            "payload_persistent": {"original_domain": "127.0.0.1"},
            "created_at": None,
            "result": {"plugins": plugins},
        }
    )


@patch("artemis.reporting.modules.wordpress_plugins.reporter.lookup_cpe_by_plugin_slug", _fake_lookup)
class WordpressPluginAssetCPETest(unittest.TestCase):
    def test_detected_plugins_carry_their_cpe(self) -> None:
        contact_form_7, kirki = _assets(
            {
                "contact-form-7": {"version": "5.9.8"},
                "kirki": {"version": "4.0.24"},
            }
        )

        self.assertEqual(contact_form_7.asset_type, AssetType.CMS_PLUGIN)
        self.assertEqual(contact_form_7.name, TARGET)
        self.assertEqual(contact_form_7.additional_type, "wordpress-plugin:contact-form-7")
        # The detected version stays in `version` - the CPE keeps its version slot wildcarded, the same
        # way the CPEs coming from Nuclei and Wappalyzer do.
        self.assertEqual(contact_form_7.version, "5.9.8")
        self.assertEqual(contact_form_7.cpe, CONTACT_FORM_7_CPE)

        # A plugin the dictionary doesn't name is still reported as an asset, just without a CPE.
        self.assertEqual(kirki.additional_type, "wordpress-plugin:kirki")
        self.assertEqual(kirki.version, "4.0.24")
        self.assertIsNone(kirki.cpe)

    def test_asset_without_version_still_gets_a_cpe(self) -> None:
        # The CPE names the product, so not knowing which version runs doesn't prevent naming it.
        (asset,) = _assets({"contact-form-7": {}})

        self.assertEqual(asset.version, "")
        self.assertEqual(asset.cpe, CONTACT_FORM_7_CPE)


if __name__ == "__main__":
    unittest.main()
