import unittest
from unittest.mock import patch

from artemis.config import Config
from artemis.crawling import _cache_key


class TestCacheKey(unittest.TestCase):
    """_cache_key is a sha256 over the normalized URL plus the config knobs that
    actually affect the crawl output."""

    def test_returns_hex_sha256(self) -> None:
        key = _cache_key("https://example.com/")
        self.assertEqual(len(key), 64)
        int(key, 16)  # raises if not valid hex

    def test_same_inputs_same_key(self) -> None:
        a = _cache_key("https://example.com/")
        b = _cache_key("https://example.com/")
        self.assertEqual(a, b)

    def test_different_url_different_key(self) -> None:
        a = _cache_key("https://example.com/")
        b = _cache_key("https://other.example/")
        self.assertNotEqual(a, b)

    def test_different_depth_different_key(self) -> None:
        with patch.object(Config.Modules.Crawling, "KATANA_DEPTH", 3):
            depth_3 = _cache_key("https://example.com/")
        with patch.object(Config.Modules.Crawling, "KATANA_DEPTH", 5):
            depth_5 = _cache_key("https://example.com/")
        self.assertNotEqual(depth_3, depth_5)

    def test_different_max_urls_different_key(self) -> None:
        with patch.object(Config.Modules.Crawling, "KATANA_MAX_URLS", 1000):
            cap_1k = _cache_key("https://example.com/")
        with patch.object(Config.Modules.Crawling, "KATANA_MAX_URLS", 2000):
            cap_2k = _cache_key("https://example.com/")
        self.assertNotEqual(cap_1k, cap_2k)

    def test_different_user_agent_different_key(self) -> None:
        with patch.object(Config.Miscellaneous, "CUSTOM_USER_AGENT", ""):
            default_ua = _cache_key("https://example.com/")
        with patch.object(Config.Miscellaneous, "CUSTOM_USER_AGENT", "MyBot/1.0"):
            custom_ua = _cache_key("https://example.com/")
        self.assertNotEqual(default_ua, custom_ua)

    def test_timeout_does_not_affect_key(self) -> None:
        # KATANA_TIMEOUT_SECONDS is not part of the cache-relevant subset:
        # changing it must NOT invalidate previously cached crawl results.
        with patch.object(Config.Modules.Crawling, "KATANA_TIMEOUT_SECONDS", 60):
            short = _cache_key("https://example.com/")
        with patch.object(Config.Modules.Crawling, "KATANA_TIMEOUT_SECONDS", 600):
            long = _cache_key("https://example.com/")
        self.assertEqual(short, long)


if __name__ == "__main__":
    unittest.main()
