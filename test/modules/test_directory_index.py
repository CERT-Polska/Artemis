import unittest
from test.base import ArtemisModuleTestCase
from typing import NamedTuple
from unittest.mock import MagicMock, patch

import requests_mock
from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.models import FoundURL
from artemis.modules.directory_index import DirectoryIndex


class TestData(NamedTuple):
    host: str
    task_type: TaskType


class DirectoryIndexTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = DirectoryIndex  # type: ignore

    def test_simple(self) -> None:
        data = [
            TestData("test-service-with-directory-index", TaskType.SERVICE),
        ]

        for entry in data:
            with requests_mock.Mocker(real_http=True) as requests_mocker:
                requests_mocker.get(
                    "https://s3.amazonaws.com/bucket1/",
                    text='<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>',
                )
                requests_mocker.get(
                    "https://bucket2.s3.amazonaws.com/",
                    text='<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>',
                )

                self.mock_db.reset_mock()
                task = Task(
                    {"type": entry.task_type, "service": Service.HTTP},
                    payload={"host": entry.host, "port": 80},
                )
                self.run_task(task)
                (call,) = self.mock_db.save_task_result.call_args_list
                self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
                self.assertEqual(
                    call.kwargs["status_reason"],
                    "Found directories with index enabled: "
                    "http://test-service-with-directory-index:80/wp-content/, "
                    "http://test-service-with-directory-index:80/wp-content/uploads/, "
                    "http://test-service-with-directory-index:80/wp-content/uploads/2022/, "
                    "http://test-service-with-directory-index:80/wp-content/uploads/2022/02/, "
                    "http://test-service-with-directory-index:80/wp-content/uploads/2022/03/, "
                    "https://bucket2.s3.amazonaws.com/, https://s3.amazonaws.com/bucket1/",
                )
                self.assertEqual(
                    sorted([item["url"] for item in call.kwargs["data"]]),
                    [
                        "http://test-service-with-directory-index:80/wp-content/",
                        "http://test-service-with-directory-index:80/wp-content/uploads/",
                        "http://test-service-with-directory-index:80/wp-content/uploads/2022/",
                        "http://test-service-with-directory-index:80/wp-content/uploads/2022/02/",
                        "http://test-service-with-directory-index:80/wp-content/uploads/2022/03/",
                        "https://bucket2.s3.amazonaws.com/",
                        "https://s3.amazonaws.com/bucket1/",
                    ],
                )


class DirectoryIndexScanTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = DirectoryIndex.__new__(DirectoryIndex)
        self.requested_urls: list[str] = []

    def _scan(self, base_url: str, pages: dict[str, str]) -> list[FoundURL]:
        def http_get(url: str) -> MagicMock:
            self.requested_urls.append(url)
            return MagicMock(content=pages.get(url, ""))

        with patch.object(self.scanner, "http_get", side_effect=http_get):
            return self.scanner.scan(base_url)

    def test_absolute_links_to_the_same_origin_are_checked(self) -> None:
        found_urls = self._scan(
            "https://example.com:443",
            {
                "https://example.com:443": (
                    '<img src="https://example.com/wp-content/uploads/2022/02/image.gif">'
                    '<a href="//EXAMPLE.com/files/doc.pdf"></a>'
                    '<a href="http://example.com/insecure/doc.pdf"></a>'
                    '<a href="https://example.com:8443/other-port/doc.pdf"></a>'
                    '<a href="https://other.example.org/private/doc.pdf"></a>'
                ),
                "https://example.com:443/wp-content/uploads/": "<title>Index of /wp-content/uploads</title>",
                "https://example.com:443/files/": "<title>Index of /files</title>",
            },
        )

        self.assertEqual(
            sorted(item.url for item in found_urls),
            ["https://example.com:443/files/", "https://example.com:443/wp-content/uploads/"],
        )
        for url in self.requested_urls:
            self.assertNotIn("/insecure/", url)
            self.assertNotIn("/other-port/", url)
            self.assertNotIn("/private/", url)

    def test_link_with_invalid_port_is_skipped(self) -> None:
        found_urls = self._scan(
            "http://example.com:80",
            {
                "http://example.com:80": '<a href="http://example.com:notaport/a/b.txt"></a><a href="/c/d.txt"></a>',
                "http://example.com:80/c/": "<title>Index of /c</title>",
            },
        )

        self.assertEqual([item.url for item in found_urls], ["http://example.com:80/c/"])
