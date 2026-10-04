from test.base import BaseReportingTest
from unittest.mock import patch

from artemis.modules.command_injection_detector import CommandInjectionDetector


class CommandInjectionDetectorIntegrationTest(BaseReportingTest):
    karton_class = CommandInjectionDetector  # type: ignore

    def test_reporting_output_based_only(self) -> None:
        # The default config stops at the first (output-based) finding, so the time-based note is absent.
        data = self.obtain_http_task_result("command_injection_detector", "test-apache-with-command-injection.local")
        message = self.task_result_to_message(data)

        self.assertIn(
            "We identified that the following URLs are vulnerable to OS command injection:",
            message,
        )
        self.assertNotIn("This was detected using a time-based (blind) technique", message)

    def test_reporting_output_and_time_based(self) -> None:
        with patch("artemis.config.Config.Modules.CommandInjectionDetector") as mocked_config:
            mocked_config.COMMAND_INJECTION_STOP_ON_FIRST_MATCH = False
            mocked_config.COMMAND_INJECTION_MINIMAL_PARAMS_MAX_LEN = 5
            mocked_config.COMMAND_INJECTION_TIME_THRESHOLD = 5
            mocked_config.COMMAND_INJECTION_NUM_RETRIES_TIME_BASED = 2
            data = self.obtain_http_task_result(
                "command_injection_detector", "test-apache-with-command-injection.local"
            )
            message = self.task_result_to_message(data)

        self.assertIn(
            "We identified that the following URLs are vulnerable to OS command injection:",
            message,
        )
        self.assertIn("This was detected using a time-based (blind) technique", message)
