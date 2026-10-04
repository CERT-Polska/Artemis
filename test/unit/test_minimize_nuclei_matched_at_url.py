import unittest
import urllib.parse
from typing import Callable, Set

from artemis.reporting.modules.nuclei.poc_url_utils import (
    minimize_nuclei_matched_at_url,
)


def _param_names(url: str) -> list[str]:
    return list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query, keep_blank_values=True).keys())


def _raw_query(url: str) -> str:
    return urllib.parse.urlparse(url).query


def _confirms(*names: str) -> Callable[[str], Set[str]]:
    """Fake refuzz_fn for a finding that each of ``names`` triggers on its own.

    It only reports the names actually present in the URL it is called with,
    so re-fuzzing the shortened URL keeps confirming the finding - the normal
    case, where the dropped parameters were irrelevant.
    """

    def refuzz(url: str) -> Set[str]:
        return set(names) & set(_param_names(url))

    return refuzz


def _confirms_only_with_gate(name: str, gate: str) -> Callable[[str], Set[str]]:
    """Fake refuzz_fn for a finding that Nuclei reports against ``name``, but
    that only reproduces while ``gate`` is also present in the URL.

    This is the ``if (isset($_GET["login"])) { echo $_GET["search"]; }`` case:
    single mode mutates ``search`` while still sending ``login``, so it reports
    ``search`` alone - dropping ``login`` would break the PoC.
    """

    def refuzz(url: str) -> Set[str]:
        names = set(_param_names(url))
        return {name} if {name, gate} <= names else set()

    return refuzz


class TestMinimizeNucleiMatchedAtUrl(unittest.TestCase):
    URL = "http://example.com/?next=PAYLOAD&category=PAYLOAD&page=testing&view=testing&q=testing&s=testing"

    def test_multiple_confirmed_all_kept(self) -> None:
        result = minimize_nuclei_matched_at_url(self.URL, refuzz_fn=_confirms("next", "category"))
        self.assertEqual(sorted(_param_names(result)), ["category", "next"])

    def test_single_confirmed_only_that_one(self) -> None:
        result = minimize_nuclei_matched_at_url(self.URL, refuzz_fn=_confirms("next"))
        self.assertEqual(_param_names(result), ["next"])

    def test_nothing_confirmed_falls_back_to_full(self) -> None:
        result = minimize_nuclei_matched_at_url(self.URL, refuzz_fn=lambda _: set())
        self.assertEqual(result, self.URL)

    def test_no_refuzz_fn_returns_full(self) -> None:
        result = minimize_nuclei_matched_at_url(self.URL, refuzz_fn=None)
        self.assertEqual(result, self.URL)

    def test_confirmed_name_absent_from_url_ignored(self) -> None:
        result = minimize_nuclei_matched_at_url(self.URL, refuzz_fn=_confirms("next", "doesnotexist"))
        self.assertEqual(_param_names(result), ["next"])

    def test_few_params_not_minimized(self) -> None:
        short = "http://example.com/?a=1&b=2"
        result = minimize_nuclei_matched_at_url(short, refuzz_fn=_confirms("a"))
        self.assertEqual(result, short)

    def test_no_query_returned_unchanged(self) -> None:
        url = "http://example.com/path"
        self.assertEqual(minimize_nuclei_matched_at_url(url, refuzz_fn=_confirms("a")), url)

    def test_payload_preserved_byte_for_byte(self) -> None:
        url = "http://example.com/?url=%2F%2Fevil.example.com%2F&a=testing&b=testing"
        result = minimize_nuclei_matched_at_url(url, refuzz_fn=_confirms("url"))
        self.assertEqual(_raw_query(result), "url=%2F%2Fevil.example.com%2F")

    def test_equals_sign_in_value_preserved(self) -> None:
        url = "http://example.com/?redirect=http://evil/?a=b%26c=d&x=testing&y=testing&z=testing"
        result = minimize_nuclei_matched_at_url(url, refuzz_fn=_confirms("redirect"))
        self.assertEqual(_raw_query(result), "redirect=http://evil/?a=b%26c=d")

    def test_param_without_value_preserved(self) -> None:
        url = "http://example.com/?debug&next=PAYLOAD&a=testing&b=testing"
        result = minimize_nuclei_matched_at_url(url, refuzz_fn=_confirms("debug", "next"))
        self.assertEqual(_raw_query(result), "debug&next=PAYLOAD")

    def test_original_order_preserved(self) -> None:
        url = "http://example.com/?zzz=PAYLOAD&aaa=PAYLOAD&mmm=testing&nnn=testing"
        result = minimize_nuclei_matched_at_url(url, refuzz_fn=_confirms("aaa", "zzz"))
        self.assertEqual(_raw_query(result), "zzz=PAYLOAD&aaa=PAYLOAD")

    def test_reported_param_needing_a_gate_falls_back_to_full(self) -> None:
        """The reported parameter is not trusted on its own: if the finding
        stops reproducing once the other parameters are dropped, the full URL
        is kept."""
        url = "http://example.com/?login=testing&search=PAYLOAD&q=testing&s=testing"
        result = minimize_nuclei_matched_at_url(url, refuzz_fn=_confirms_only_with_gate("search", "login"))
        self.assertEqual(result, url)

    def test_verification_runs_on_the_shortened_url(self) -> None:
        """The second re-fuzz must be given the shortened URL, not the original
        one - otherwise it would confirm the very parameters it is meant to
        check we can drop."""
        seen: list[str] = []

        def refuzz(url: str) -> Set[str]:
            seen.append(url)
            return {"next"}

        result = minimize_nuclei_matched_at_url(self.URL, refuzz_fn=refuzz)
        self.assertEqual(_param_names(result), ["next"])
        self.assertEqual(seen, [self.URL, "http://example.com/?next=PAYLOAD"])

    def test_all_params_confirmed_skips_verification(self) -> None:
        """If nothing would be dropped, the URL is returned as-is without a
        second Nuclei run."""
        url = "http://example.com/?a=PAYLOAD&b=PAYLOAD&c=PAYLOAD"
        calls: list[str] = []

        def refuzz(refuzzed_url: str) -> Set[str]:
            calls.append(refuzzed_url)
            return {"a", "b", "c"}

        result = minimize_nuclei_matched_at_url(url, refuzz_fn=refuzz)
        self.assertEqual(result, url)
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
