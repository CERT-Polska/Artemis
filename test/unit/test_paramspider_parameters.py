import unittest
from unittest.mock import MagicMock, patch

from artemis.crawling import _fetch_paramspider_parameters, get_paramspider_parameters


class TestGetParamSpiderParameters(unittest.TestCase):
    def setUp(self) -> None:
        _fetch_paramspider_parameters.cache_clear()

    def tearDown(self) -> None:
        _fetch_paramspider_parameters.cache_clear()

    def _mock_paramspider(self, urls: list[str]) -> MagicMock:
        output_content = "\n".join(urls)

        def fake_run(cmd: list[str], **kwargs: object) -> None:
            output_file = cmd[cmd.index("--output") + 1]
            with open(output_file, "w") as f:
                f.write(output_content)

        return fake_run

    @patch("artemis.crawling.subprocess.run")
    def test_extracts_parameters(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = self._mock_paramspider(
            [
                "http://example.com/search?q=test&lang=en",
                "http://example.com/page?id=1",
            ]
        )

        result = get_paramspider_parameters("http://example.com/")
        self.assertEqual(sorted(result), ["id", "lang", "q"])

    @patch("artemis.crawling.subprocess.run")
    def test_deduplicates_parameters(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = self._mock_paramspider(
            [
                "http://example.com/page?id=1",
                "http://example.com/page?id=2",
            ]
        )

        result = get_paramspider_parameters("http://example.com/")
        self.assertEqual(result, ["id"])

    @patch("artemis.crawling.subprocess.run")
    def test_no_output_file_returns_empty_list(self, mock_run: MagicMock) -> None:
        mock_run.return_value = None

        result = get_paramspider_parameters("http://example.com/")
        self.assertEqual(result, [])

    @patch("artemis.crawling.subprocess.run")
    def test_failure_returns_empty_list(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = Exception("paramspider not found")

        result = get_paramspider_parameters("http://example.com/")
        self.assertEqual(result, [])

    def test_invalid_url_returns_empty_list(self) -> None:
        result = get_paramspider_parameters("not-a-url")
        self.assertEqual(result, [])

    @patch("artemis.crawling.subprocess.run")
    def test_results_cached_per_domain(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = self._mock_paramspider(
            ["http://example.com/page?foo=1"]
        )

        get_paramspider_parameters("http://example.com/path/a")
        get_paramspider_parameters("http://example.com/path/b")

        mock_run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
