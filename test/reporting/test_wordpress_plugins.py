from unittest import TestCase
from unittest.mock import MagicMock, patch

from artemis.reporting.modules.wordpress_plugins.reporter import (
    WordpressPluginsReporter,
)


class WordpressPluginsReporterTest(TestCase):
    def test_is_version_known_to_wordpress(self) -> None:
        with patch("artemis.reporting.modules.wordpress_plugins.reporter.FallbackAPICache.get") as mock_get:
            mock_response_found = MagicMock()
            mock_response_found.status_code = 200
            mock_response_found.text = "Version <strong>2.0.4.1</strong>"

            mock_response_not_found = MagicMock()
            mock_response_not_found.status_code = 404

            # First call: version found and equals (2.0.4.0 < 2.0.4.1 so true)
            # Actually the logic is: if latest_version == plugin_version OR latest >= plugin
            # Case 1: 2.0.4.0 vs latest 2.0.4.1 -> True
            # Case 2: 2.0.4.1 vs latest 2.0.4.1 -> True
            # Case 3: 2.0.4.2 vs latest 2.0.4.1 -> False

            # We need to configure the mock to return the same response for all calls
            # or different responses if needed. The test checks against "sitepress-multilingual-cms".
            # The test expects 2.0.4.1 to be the latest version to make the assertions pass.

            mock_get.return_value = mock_response_found

            self.assertTrue(
                WordpressPluginsReporter.is_version_known_to_wordpress("sitepress-multilingual-cms", "2.0.4.0")
            )
            self.assertTrue(
                WordpressPluginsReporter.is_version_known_to_wordpress("sitepress-multilingual-cms", "2.0.4.1")
            )
            self.assertFalse(
                WordpressPluginsReporter.is_version_known_to_wordpress("sitepress-multilingual-cms", "2.0.4.2")
            )
