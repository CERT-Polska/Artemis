# type: ignore
from test.base import ArtemisModuleTestCase
from unittest.mock import patch

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.lfi_detector import LFIDetector


class LFIDetectorTestCase(ArtemisModuleTestCase):
    karton_class = LFIDetector

    def test_lfi_detector_with_rce(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "test-apache-with-lfi-and-rce", "port": 80},
        )

        with patch("artemis.config.Config.Modules.LFIDetector") as mocked_config:
            mocked_config.LFI_STOP_ON_FIRST_MATCH = False
            self.run_task(task)
            (call,) = self.mock_db.save_task_result.call_args_list

            self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
            self.assertIn(
                "It appears that this URL is vulnerable to LFI: " "http://test-apache-with-lfi-and-rce:80/page.php?id=",
                call.kwargs["status_reason"],
            )

            self.assertIn(
                "etc/passwd",
                call.kwargs["status_reason"],
            )
            self.assertIn(
                "It appears that this URL is vulnerable to RCE: " "http://test-apache-with-lfi-and-rce:80/page.php?id=",
                call.kwargs["status_reason"],
            )

            self.assertIn(
                "%0a/bin/cat%20/etc/passwd",
                call.kwargs["status_reason"],
            )
