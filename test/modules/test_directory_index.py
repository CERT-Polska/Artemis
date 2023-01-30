from test.base import ArtemisModuleTestCase
from typing import NamedTuple

import requests_mock
from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
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
