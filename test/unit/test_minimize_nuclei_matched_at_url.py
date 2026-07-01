import unittest
import urllib.parse

from artemis.reporting.modules.nuclei.poc_url_utils import (
    minimize_nuclei_matched_at_url,
)


def _param_names(url: str) -> list[str]:
    return list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())


def _raw_query(url: str) -> str:
    return urllib.parse.urlparse(url).query


class TestMinimizeNucleiMatchedAtUrl(unittest.TestCase):
    URL = "http://ex.com/?next=PAYLOAD&category=PAYLOAD&page=testing&view=testing&q=testing&s=testing"

    def test_multiple_confirmed_all_kept(self) -> None:
        result = minimize_nuclei_matched_at_url(self.URL, refuzz_fn=lambda _: {"next", "category"})
        self.assertEqual(sorted(_param_names(result)), ["category", "next"])

    def test_single_confirmed_only_that_one(self) -> None:
        result = minimize_nuclei_matched_at_url(self.URL, refuzz_fn=lambda _: {"next"})
        self.assertEqual(_param_names(result), ["next"])

    def test_nothing_confirmed_falls_back_to_full(self) -> None:
        result = minimize_nuclei_matched_at_url(self.URL, refuzz_fn=lambda _: set())
        self.assertEqual(result, self.URL)

    def test_no_refuzz_fn_returns_full(self) -> None:
        result = minimize_nuclei_matched_at_url(self.URL, refuzz_fn=None)
        self.assertEqual(result, self.URL)

    def test_confirmed_name_absent_from_url_ignored(self) -> None:
        result = minimize_nuclei_matched_at_url(self.URL, refuzz_fn=lambda _: {"next", "doesnotexist"})
        self.assertEqual(_param_names(result), ["next"])

    def test_few_params_not_minimized(self) -> None:
        short = "http://ex.com/?a=1&b=2"
        result = minimize_nuclei_matched_at_url(short, refuzz_fn=lambda _: {"a"})
        self.assertEqual(result, short)

    def test_no_query_returned_unchanged(self) -> None:
        url = "http://ex.com/path"
        self.assertEqual(minimize_nuclei_matched_at_url(url, refuzz_fn=lambda _: {"a"}), url)

    def test_payload_preserved_byte_for_byte(self) -> None:
        url = "http://ex.com/?url=%2F%2Fevil.example.com%2F&a=testing&b=testing"
        result = minimize_nuclei_matched_at_url(url, refuzz_fn=lambda _: {"url"})
        self.assertEqual(_raw_query(result), "url=%2F%2Fevil.example.com%2F")

    def test_equals_sign_in_value_preserved(self) -> None:
        url = "http://ex.com/?redirect=http://evil/?a=b%26c=d&x=testing&y=testing&z=testing"
        result = minimize_nuclei_matched_at_url(url, refuzz_fn=lambda _: {"redirect"})
        self.assertEqual(_raw_query(result), "redirect=http://evil/?a=b%26c=d")

    def test_param_without_value_preserved(self) -> None:
        url = "http://ex.com/?debug&next=PAYLOAD&a=testing&b=testing"
        result = minimize_nuclei_matched_at_url(url, refuzz_fn=lambda _: {"debug", "next"})
        self.assertEqual(_raw_query(result), "debug&next=PAYLOAD")

    def test_original_order_preserved(self) -> None:
        url = "http://ex.com/?zzz=PAYLOAD&aaa=PAYLOAD&mmm=testing&nnn=testing"
        result = minimize_nuclei_matched_at_url(url, refuzz_fn=lambda _: {"aaa", "zzz"})
        self.assertEqual(_raw_query(result), "zzz=PAYLOAD&aaa=PAYLOAD")


if __name__ == "__main__":
    unittest.main()
