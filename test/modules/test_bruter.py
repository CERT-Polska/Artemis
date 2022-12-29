from test.base import ArtemisModuleTestCase
from typing import NamedTuple

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.bruter import Bruter


class TestData(NamedTuple):
    host: str
    task_type: TaskType


class BruterTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = Bruter  # type: ignore

    def test_simple(self) -> None:
        data = [
            TestData("test-service-with-bruteable-files", TaskType.SERVICE),
        ]

        for entry in data:
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
                f"Found URLs: http://{entry.host}:80/config.dist, "
                f"http://{entry.host}:80/localhost.sql, "
                f"http://{entry.host}:80/sql.gz, "
                f"http://{entry.host}:80/test "
                f"(http://{entry.host}:80/test with directory index)",
            )

            self.assertEqual(
                call.kwargs["data"]["found_urls"],
                [
                    {
                        "url": "http://test-service-with-bruteable-files:80/config.dist",
                        "content_prefix": "...\n",
                        "has_directory_index": False,
                    },
                    {
                        "url": "http://test-service-with-bruteable-files:80/localhost.sql",
                        "content_prefix": ".\n",
                        "has_directory_index": False,
                    },
                    {
                        "url": "http://test-service-with-bruteable-files:80/sql.gz",
                        "content_prefix": "...\n",
                        "has_directory_index": False,
                    },
                    {
                        "url": "http://test-service-with-bruteable-files:80/test",
                        "content_prefix": (
                            '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">\n<html>\n <head>\n  <title>Index of '
                            '/test</title>\n </head>\n <body>\n<h1>Index of /test</h1>\n  <table>\n   <tr><th valign="top">'
                            '<img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th>'
                            '<a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a '
                            'href="?C=D;O=A">Description</a></th></tr>\n   <tr><th colspan="5"><hr></th></tr>\n<tr>'
                            '<td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent '
                            'Directory</a>       </td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>\n'
                            '<tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="main/">main/'
                            '</a>                  </td><td align="right">2008-02-21 11:32  </td><td align="right">  - '
                            '</td><td>&nbsp;</td></tr>\n   <tr><th colspan="5"><hr></th></tr>\n</table>\n</body></html>\n'
                        ),
                        "has_directory_index": True,
                    },
                ],
            )
