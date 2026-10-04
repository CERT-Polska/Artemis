from test.base import BaseReportingTest
from typing import Any
from unittest.mock import MagicMock, patch

from artemis.binds import WebApplication
from artemis.cpe_tools.cpe_main_process import VERSION_FIELD_INDEX, split_cpe
from artemis.fallback_api_cache import FallbackAPICache
from artemis.modules.wordpress_plugins import WordpressPlugins
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporters import assets_from_task_result

URL = "http://test-wordpress-with-plugins:80/"

# The plugins the test-wordpress-with-plugins fixture serves a readme for, and the version the
# WordPress repository is pretended to have. Both are ahead of the installed one, so both plugins are
# reported as outdated - what matters here is only that both are turned into assets.
REPOSITORY_VERSIONS = {"contact-form-7": "5.9.9", "kirki": "4.0.25"}

# Contact Form 7 is in the mock CPE dictionary (test/data/mock_nvd_cpe), which names it through the
# wordpress.org/plugins/contact-form-7/ reference its CPEs carry. Kirki is not in there.
CONTACT_FORM_7_CPE = "cpe:2.3:a:rocklobster:contact_form_7:*:*:*:*:*:wordpress:*:*"


def _wordpress_org_response(url: str, allow_unknown: bool = False) -> MagicMock:
    """Answers the api.wordpress.org calls the module makes, so that the test needs no network.

    Only the module's own dependency on the WordPress plugin repository is stood in for here. The CPE
    lookup, which is what this test is about, runs for real against the mock dictionary.
    """
    payload: Any
    if "action=query_plugins" in url:
        payload = {
            "info": {"page": 1},
            "plugins": [
                {"name": slug, "slug": slug, "version": version} for slug, version in REPOSITORY_VERSIONS.items()
            ],
        }
    elif "/plugins/info/1.0/" in url:
        payload = {"version": REPOSITORY_VERSIONS[url.rsplit("/", 1)[-1].removesuffix(".json")]}
    elif "/stats/plugin/1.0/" in url:
        # A non-empty stats response means the plugin is still in the repository, i.e. not a closed one.
        payload = {"6.5": 100.0}
    else:
        raise AssertionError(f"Unexpected wordpress.org request: {url}")

    response = MagicMock()
    response.status_code = 200
    response.json.return_value = payload
    return response


class WordpressPluginsAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = WordpressPlugins  # type: ignore

    def setUp(self) -> None:
        wordpress_org_patcher = patch.object(FallbackAPICache, "get", side_effect=_wordpress_org_response)
        wordpress_org_patcher.start()
        self.addCleanup(wordpress_org_patcher.stop)
        super().setUp()

    def test_asset_discovery(self) -> None:
        data = self.obtain_webapp_task_result("wordpress_plugins", WebApplication.WORDPRESS, URL)
        assets = {asset.additional_type: asset for asset in assets_from_task_result(data)}

        self.assertEqual(set(assets), {"wordpress-plugin:contact-form-7", "wordpress-plugin:kirki"})

        contact_form_7 = assets["wordpress-plugin:contact-form-7"]
        self.assertEqual(contact_form_7.asset_type, AssetType.CMS_PLUGIN)
        self.assertEqual(contact_form_7.name, URL)
        cpe = contact_form_7.cpe
        self.assertEqual(cpe, CONTACT_FORM_7_CPE)
        assert cpe is not None  # narrowing for split_cpe below
        # The detected version stays in `version` - the CPE names the product, keeping "*" in its
        # version slot, the same way the CPEs coming from Nuclei and Wappalyzer do.
        self.assertEqual(contact_form_7.version, "5.9.8")
        self.assertEqual(split_cpe(cpe)[VERSION_FIELD_INDEX], "*")

        # A plugin the dictionary doesn't name is still reported as an asset, just without a CPE.
        # On its own this assertion carries no weight - an empty dictionary satisfies it just as well.
        # It means something only because contact-form-7 above has already shown that the dictionary
        # is loaded, so the two belong in one test method and should not be split apart.
        kirki = assets["wordpress-plugin:kirki"]
        self.assertEqual(kirki.asset_type, AssetType.CMS_PLUGIN)
        self.assertEqual(kirki.version, "4.0.24")
        self.assertIsNone(kirki.cpe)
