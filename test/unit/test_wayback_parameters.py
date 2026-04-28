import unittest
from unittest.mock import MagicMock, patch

from artemis.crawling import _fetch_wayback_parameters, get_wayback_parameters


def _make_cdx_response(urls: list[str], status_code: int = 200) -> MagicMock:
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = [["original"]] + [[url] for url in urls]
    mock.raise_for_status = MagicMock()
    return mock


class TestGetWaybackParameters(unittest.TestCase):
    def setUp(self) -> None:
        _fetch_wayback_parameters.cache_clear()

    def tearDown(self) -> None:
        _fetch_wayback_parameters.cache_clear()

    @patch("artemis.crawling.requests.get")
    def test_extracts_parameters_from_historical_urls(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_cdx_response(
            [
                "http://example.com/search?q=test&lang=en",
                "http://example.com/page?id=1",
                "http://example.com/page?id=2&category=news",
            ]
        )

        result = get_wayback_parameters("http://example.com/")
        self.assertEqual(sorted(result), ["category", "id", "lang", "q"])

    @patch("artemis.crawling.requests.get")
    def test_deduplicates_parameters(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_cdx_response(
            [
                "http://example.com/page?id=1",
                "http://example.com/page?id=2",
                "http://example.com/page?id=3",
            ]
        )

        result = get_wayback_parameters("http://example.com/")
        self.assertEqual(result, ["id"])

    @patch("artemis.crawling.requests.get")
    def test_empty_response_returns_empty_list(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_cdx_response([])

        result = get_wayback_parameters("http://example.com/")
        self.assertEqual(result, [])

    @patch("artemis.crawling.requests.get")
    def test_urls_without_params_return_empty_list(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_cdx_response(
            [
                "http://example.com/about",
                "http://example.com/contact",
            ]
        )

        result = get_wayback_parameters("http://example.com/")
        self.assertEqual(result, [])

    @patch("artemis.crawling.requests.get")
    def test_network_failure_returns_empty_list(self, mock_get: MagicMock) -> None:
        mock_get.side_effect = Exception("connection error")

        result = get_wayback_parameters("http://example.com/")
        self.assertEqual(result, [])

    @patch("artemis.crawling.requests.get")
    def test_results_cached_per_domain(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_cdx_response(
            [
                "http://example.com/page?foo=1",
            ]
        )

        get_wayback_parameters("http://example.com/path/a")
        get_wayback_parameters("http://example.com/path/b")

        # Both calls share the same domain, only one CDX request
        mock_get.assert_called_once()

    @patch("artemis.crawling.requests.get")
    def test_different_domains_cached_independently(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_cdx_response(
            [
                "http://example.com/page?foo=1",
            ]
        )

        get_wayback_parameters("http://example.com/")
        get_wayback_parameters("http://other.com/")

        self.assertEqual(mock_get.call_count, 2)

    def test_invalid_url_returns_empty_list(self) -> None:
        result = get_wayback_parameters("not-a-url")
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
