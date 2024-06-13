from unittest import TestCase

from artemis.reporting.modules.wordpress_plugins.reporter import (
    WordpressPluginsReporter,
)


class WordpressPluginsReporterTest(TestCase):
    def test_is_version_known_to_wordpress(self) -> None:
        self.assertTrue(WordpressPluginsReporter.is_version_known_to_wordpress("sitepress-multilingual-cms", "2.0.4.0"))
        self.assertTrue(WordpressPluginsReporter.is_version_known_to_wordpress("sitepress-multilingual-cms", "2.0.4.1"))
        self.assertFalse(
            WordpressPluginsReporter.is_version_known_to_wordpress("sitepress-multilingual-cms", "2.0.4.2")
        )
