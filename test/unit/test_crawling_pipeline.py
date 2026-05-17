import json
import subprocess
import unittest
from typing import Iterable
from unittest.mock import MagicMock, patch

from artemis import crawling
from artemis.config import Config
from artemis.resource_lock import FailedToAcquireLockException


def _katana_jsonl(urls: Iterable[str]) -> bytes:
    return b"".join((json.dumps({"request": {"endpoint": u}}) + "\n").encode() for u in urls)


def _katana_proc(stdout: bytes, *, raises_timeout: bool = False) -> MagicMock:
    proc = MagicMock()
    if raises_timeout:
        proc.communicate.side_effect = [
            subprocess.TimeoutExpired(cmd="katana", timeout=120),
            (stdout, b""),
        ]
    else:
        proc.communicate.return_value = (stdout, b"")
    proc.returncode = 0
    return proc


class TestCrawlAndFilter(unittest.TestCase):
    """End-to-end tests for crawl_and_filter with all subprocesses, the Redis
    cache, and the distributed lock mocked."""

    def setUp(self) -> None:
        self.cache_patcher = patch.object(crawling, "_CRAWL_CACHE")
        self.mock_cache = self.cache_patcher.start()
        self.mock_cache.get.return_value = None  # default: cache miss

        self.lock_patcher = patch.object(crawling, "ResourceLock")
        self.mock_lock_cls = self.lock_patcher.start()
        self.mock_lock = MagicMock()
        self.mock_lock_cls.return_value = self.mock_lock

    def tearDown(self) -> None:
        self.cache_patcher.stop()
        self.lock_patcher.stop()

    def test_cache_hit_skips_katana_and_lock(self) -> None:
        cached = json.dumps(["https://example.com/a", "https://example.com/b.js"]).encode()
        self.mock_cache.get.return_value = cached
        with (
            patch("artemis.crawling.subprocess.Popen") as mock_popen,
            patch("artemis.crawling.subprocess.run") as mock_run,
        ):
            result = crawling.crawl_and_filter("https://example.com/")
        mock_popen.assert_not_called()
        mock_run.assert_not_called()
        self.mock_lock.acquire.assert_not_called()
        self.assertEqual(result, ["https://example.com/a", "https://example.com/b.js"])

    def test_cache_miss_runs_pipeline_and_writes_cache_with_full_ttl(self) -> None:
        with (
            patch("artemis.crawling.subprocess.Popen") as mock_popen,
            patch("artemis.crawling.subprocess.run") as mock_run,
        ):
            mock_popen.return_value = _katana_proc(_katana_jsonl(["https://example.com/a", "https://example.com/b.js"]))
            mock_run.return_value = MagicMock(stdout=b"https://example.com/a\nhttps://example.com/b.js\n")
            result = crawling.crawl_and_filter("https://example.com/")

        mock_popen.assert_called_once()
        self.assertEqual(mock_run.call_args.args[0], ["uro"])
        set_kwargs = self.mock_cache.set.call_args.kwargs
        self.assertEqual(set_kwargs["timeout"], Config.Modules.Crawling.CRAWL_CACHE_TTL_SECONDS)
        self.mock_lock.release.assert_called_once()
        self.assertIn("https://example.com/a", result)
        self.assertIn("https://example.com/b.js", result)

    def test_katana_timeout_caches_partial_with_short_ttl(self) -> None:
        partial = _katana_jsonl(["https://example.com/partial"])
        with (
            patch("artemis.crawling.subprocess.Popen") as mock_popen,
            patch("artemis.crawling.subprocess.run") as mock_run,
        ):
            proc = _katana_proc(partial, raises_timeout=True)
            mock_popen.return_value = proc
            mock_run.return_value = MagicMock(stdout=b"https://example.com/partial\n")
            result = crawling.crawl_and_filter("https://example.com/")

        proc.kill.assert_called_once()
        set_kwargs = self.mock_cache.set.call_args.kwargs
        self.assertEqual(
            set_kwargs["timeout"],
            Config.Modules.Crawling.KATANA_TIMEOUT_CACHE_TTL_SECONDS,
        )
        self.assertIn("https://example.com/partial", result)

    def test_uro_failure_falls_back_to_naive_dedup(self) -> None:
        with (
            patch("artemis.crawling.subprocess.Popen") as mock_popen,
            patch(
                "artemis.crawling.subprocess.run",
                side_effect=FileNotFoundError("uro missing"),
            ),
        ):
            mock_popen.return_value = _katana_proc(
                _katana_jsonl(
                    [
                        "https://example.com/a",
                        "https://example.com/a",  # duplicate, must dedup
                        "https://example.com/b",
                    ]
                )
            )
            result = crawling.crawl_and_filter("https://example.com/")

        self.assertEqual(set(result), {"https://example.com/a", "https://example.com/b"})

    def test_scope_post_filter_drops_out_of_scope_urls(self) -> None:
        with (
            patch("artemis.crawling.subprocess.Popen") as mock_popen,
            patch("artemis.crawling.subprocess.run") as mock_run,
        ):
            mock_popen.return_value = _katana_proc(
                _katana_jsonl(
                    [
                        "https://example.com/in-scope",
                        "https://attacker.com/leak",
                    ]
                )
            )
            mock_run.return_value = MagicMock(stdout=b"https://example.com/in-scope\nhttps://attacker.com/leak\n")
            result = crawling.crawl_and_filter("https://example.com/")

        self.assertIn("https://example.com/in-scope", result)
        self.assertNotIn("https://attacker.com/leak", result)

    def test_lock_contention_runs_uncached_and_does_not_write_cache(self) -> None:
        self.mock_lock.acquire.side_effect = FailedToAcquireLockException()
        with (
            patch("artemis.crawling.subprocess.Popen") as mock_popen,
            patch("artemis.crawling.subprocess.run") as mock_run,
        ):
            mock_popen.return_value = _katana_proc(_katana_jsonl(["https://example.com/a"]))
            mock_run.return_value = MagicMock(stdout=b"https://example.com/a\n")
            result = crawling.crawl_and_filter("https://example.com/")

        self.assertIn("https://example.com/a", result)
        self.mock_lock.acquire.assert_called_once()
        self.mock_lock.release.assert_not_called()
        self.mock_cache.set.assert_not_called()

    def test_re_check_after_lock_acquire_uses_other_workers_cache_entry(self) -> None:
        # Race-loser path: missed the cache, acquired the lock, then found a
        # cached value written by the winning worker. Must not re-run Katana.
        cached = json.dumps(["https://example.com/from-other"]).encode()
        self.mock_cache.get.side_effect = [None, cached]
        with (
            patch("artemis.crawling.subprocess.Popen") as mock_popen,
            patch("artemis.crawling.subprocess.run") as mock_run,
        ):
            result = crawling.crawl_and_filter("https://example.com/")

        mock_popen.assert_not_called()
        mock_run.assert_not_called()
        self.assertEqual(result, ["https://example.com/from-other"])
        self.mock_lock.release.assert_called_once()
        self.mock_cache.set.assert_not_called()

    def test_malformed_jsonl_lines_are_skipped_not_raised(self) -> None:
        bad_and_good = (
            b'{"request":{"endpoint":"https://example.com/a"}}\n'
            b"not valid json\n"
            b'{"request":{}}\n'  # missing endpoint
            b'{"request":{"endpoint":"https://example.com/b"}}\n'
        )
        with (
            patch("artemis.crawling.subprocess.Popen") as mock_popen,
            patch("artemis.crawling.subprocess.run") as mock_run,
        ):
            mock_popen.return_value = _katana_proc(bad_and_good)
            mock_run.return_value = MagicMock(stdout=b"https://example.com/a\nhttps://example.com/b\n")
            result = crawling.crawl_and_filter("https://example.com/")
        self.assertCountEqual(result, ["https://example.com/a", "https://example.com/b"])


if __name__ == "__main__":
    unittest.main()
