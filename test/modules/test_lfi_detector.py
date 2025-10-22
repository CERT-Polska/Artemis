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
                "It appears that this URL is vulnerable to LFI: "
                "http://test-apache-with-lfi-and-rce:80/page.php?gmt_offset=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd&go=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd&g=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd&group=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd&group_id=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd&groups=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd&h=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd&hash=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd&height=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd&hidden=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd&history=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd&host=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd&hostname=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd&html=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd&i=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd&id=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd&ID=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd&id_base=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                call.kwargs["status_reason"],
            )
            self.assertIn(
                "It appears that this URL is vulnerable to RCE: "
                "http://test-apache-with-lfi-and-rce:80/page.php?edit=%0a/bin/cat%20/etc/passwd&email=%0a/bin/cat%20/etc/passwd&enable=%0a/bin/cat%20/etc/passwd&enabled=%0a/bin/cat%20/etc/passwd&end=%0a/bin/cat%20/etc/passwd&end_date=%0a/bin/cat%20/etc/passwd&error=%0a/bin/cat%20/etc/passwd&event=%0a/bin/cat%20/etc/passwd&excerpt=%0a/bin/cat%20/etc/passwd&export=%0a/bin/cat%20/etc/passwd&f=%0a/bin/cat%20/etc/passwd&features=%0a/bin/cat%20/etc/passwd&fid=%0a/bin/cat%20/etc/passwd&field=%0a/bin/cat%20/etc/passwd&field_id=%0a/bin/cat%20/etc/passwd&fields=%0a/bin/cat%20/etc/passwd&file=%0a/bin/cat%20/etc/passwd&file_name=%0a/bin/cat%20/etc/passwd&filename=%0a/bin/cat%20/etc/passwd&files=%0a/bin/cat%20/etc/passwd&filter=%0a/bin/cat%20/etc/passwd&firstname=%0a/bin/cat%20/etc/passwd&first_name=%0a/bin/cat%20/etc/passwd&flag=%0a/bin/cat%20/etc/passwd&fname=%0a/bin/cat%20/etc/passwd&folder=%0a/bin/cat%20/etc/passwd&foo=%0a/bin/cat%20/etc/passwd&form=%0a/bin/cat%20/etc/passwd&format=%0a/bin/cat%20/etc/passwd&from=%0a/bin/cat%20/etc/passwd&function=%0a/bin/cat%20/etc/passwd&g=%0a/bin/cat%20/etc/passwd&gid=%0a/bin/cat%20/etc/passwd&gmt_offset=%0a/bin/cat%20/etc/passwd&go=%0a/bin/cat%20/etc/passwd&group=%0a/bin/cat%20/etc/passwd&group_id=%0a/bin/cat%20/etc/passwd&groups=%0a/bin/cat%20/etc/passwd&h=%0a/bin/cat%20/etc/passwd&hash=%0a/bin/cat%20/etc/passwd&height=%0a/bin/cat%20/etc/passwd&hidden=%0a/bin/cat%20/etc/passwd&history=%0a/bin/cat%20/etc/passwd&host=%0a/bin/cat%20/etc/passwd&hostname=%0a/bin/cat%20/etc/passwd&html=%0a/bin/cat%20/etc/passwd&i=%0a/bin/cat%20/etc/passwd&id=%0a/bin/cat%20/etc/passwd&ID=%0a/bin/cat%20/etc/passwd",
                call.kwargs["status_reason"],
            )
