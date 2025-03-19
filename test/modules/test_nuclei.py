from unittest.mock import patch, MagicMock

from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import SeverityThreshold
from artemis.modules.nuclei import Nuclei


class NucleiTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = Nuclei  # type: ignore

    def test_links(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-php-xss-but-not-on-homepage",
                "port": 80,
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "[high] http://test-php-xss-but-not-on-homepage:80/xss.php: Top 38 Parameters - Cross-Site Scripting Cross-site scripting was discovered via a search for reflected parameter "
            "values in the server response via GET-requests., [medium] http://test-php-xss-but-not-on-homepage:80/xss.php: Fuzzing Parameters - Cross-Site Scripting Cross-site scripting "
            "was discovered via a search for reflected parameter values in the server response via GET-requests.\n",
        )

    @patch('artemis.config.Config.Modules.Nuclei.NUCLEI_SEVERITY_THRESHOLD', SeverityThreshold.CRITICAL_ONLY)
    @patch('artemis.utils.check_output_log_on_error')
    def test_severity_threshold_critical_only(self, mock_check_output) -> None:
        """Test that only critical severity templates are included when threshold is CRITICAL_ONLY."""
        # Mock the check_output_log_on_error function to avoid actual command execution
        mock_check_output.return_value = b""
        
        # We expect the run command to include only critical severity
        nuclei = Nuclei()
        nuclei._scan(["test_template"], ["http://example.com"])
        
        # Check that nuclei command was called with the correct severity parameter
        for call_args in mock_check_output.call_args_list:
            command = call_args[0][0]
            if 'nuclei' in command and '-s' in command:
                severity_index = command.index('-s') + 1
                self.assertEqual(command[severity_index], "critical")
                break
        else:
            self.fail("Nuclei command with -s parameter was not called")
    
    @patch('artemis.config.Config.Modules.Nuclei.NUCLEI_SEVERITY_THRESHOLD', SeverityThreshold.HIGH_AND_ABOVE)
    @patch('artemis.utils.check_output_log_on_error')
    def test_severity_threshold_high_and_above(self, mock_check_output) -> None:
        """Test that critical and high severity templates are included when threshold is HIGH_AND_ABOVE."""
        # Mock the check_output_log_on_error function to avoid actual command execution
        mock_check_output.return_value = b""
        
        # We expect the run command to include critical and high severity
        nuclei = Nuclei()
        nuclei._scan(["test_template"], ["http://example.com"])
        
        # Check that nuclei command was called with the correct severity parameter
        for call_args in mock_check_output.call_args_list:
            command = call_args[0][0]
            if 'nuclei' in command and '-s' in command:
                severity_index = command.index('-s') + 1
                self.assertEqual(command[severity_index], "critical,high")
                break
        else:
            self.fail("Nuclei command with -s parameter was not called")
