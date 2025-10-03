from test.base import BaseReportingTest
from unittest.mock import patch

from artemis.modules.lfi_detector import LFIDetector


class LFIDetectorIntegrationTest(BaseReportingTest):
    karton_class = LFIDetector  # type: ignore

    def test_reporting_only_lfi(self) -> None:
        data = self.obtain_http_task_result("lfi_detector", "test-apache-with-lfi-and-rce")
        message = self.task_result_to_message(data)

        self.assertIn(
            "We identified that the following URLs are vulnerable to Local File Inclusion (LFI):",
            message,
        )

        self.assertNotIn(
            "We identified that the following URLs are vulnerable to Remote Code Execution (RCE):",
            message,
        )

    def test_reporting_lfi_and_rce(self) -> None:
        with patch("artemis.config.Config.Modules.LFIDetector") as mocked_config:
            mocked_config.LFI_STOP_ON_FIRST_MATCH = False
            data = self.obtain_http_task_result("lfi_detector", "test-apache-with-lfi-and-rce")
            message = self.task_result_to_message(data)

            self.assertIn(
                "We identified that the following URLs are vulnerable to Local File Inclusion (LFI):",
                message,
            )

            self.assertIn(
                "We identified that the following URLs are vulnerable to Remote Code Execution (RCE):",
                message,
            )
