from test.base import ArtemisModuleTestCase
from typing import NamedTuple

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.php_lfi import LFICandidate, PHPLFIScanner, get_lfi_candidates


class TestData(NamedTuple):
    host: str
    task_type: TaskType
    result: dict


class PHPLFIScannerTest(ArtemisModuleTestCase):
    karton_class = PHPLFIScanner

    def test_get_lfi_candidates(self):
        self.assertEqual(
            get_lfi_candidates("", "<a href=include-file.php?name=test>"),
            [LFICandidate(file="include-file", param="name")],
        )
        self.assertEqual(
            get_lfi_candidates("", "<img src=include-file.php?name=test>"),
            [LFICandidate(file="include-file", param="name")],
        )
        self.assertEqual(
            get_lfi_candidates("", '<a href="include-file.php?name=test">'),
            [LFICandidate(file="include-file", param="name")],
        )
        self.assertEqual(
            get_lfi_candidates("", '<img src="include-file.php?name=test">'),
            [LFICandidate(file="include-file", param="name")],
        )

    def test_php_lfi(self) -> None:
        data = [
            TestData(
                host="test-php-lfi",
                task_type=TaskType.SERVICE,
                result={"file=lfi.php, param_name=file": "confirmed"},
            ),
        ]

        for entry in data:
            self.mock_db.reset_mock()
            task = Task(
                {"type": entry.task_type, "service": Service.HTTP},
                payload={
                    "host": entry.host,
                    "port": 80,
                    "ssl": False,
                },
            )
            self.run_task(task)
            (call,) = self.mock_db.save_task_result.call_args_list
            self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
            self.assertEqual(
                call.kwargs["status_reason"],
                "Found LFIs in http://test-php-lfi:80/lfi.php?file="
                "php://filter/convert.base64-encode/resource=lfi.php",
            )
            self.assertEqual(call.kwargs["data"], entry.result)
