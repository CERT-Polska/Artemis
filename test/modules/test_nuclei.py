from unittest.mock import patch, MagicMock

from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import SeverityThreshold
from artemis.modules.nuclei import Nuclei
from artemis.modules.nuclei_configuration import NucleiConfiguration


class NucleiTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = Nuclei  # type: ignore

    def test_get_default_configuration(self) -> None:
        """Test that get_default_configuration returns expected defaults."""
        nuclei = Nuclei()
        config = nuclei.get_default_configuration()
        
        self.assertIsInstance(config, NucleiConfiguration)
        self.assertTrue(config.enabled)
        self.assertEqual(config.severity_threshold, Config.Modules.Nuclei.NUCLEI_SEVERITY_THRESHOLD)
        self.assertIsNone(config.max_templates)
        
    def test_process_task_with_custom_configuration(self) -> None:
        """Test that process_task correctly uses custom configuration from payload."""
        custom_config = {
            "enabled": True,
            "severity_threshold": SeverityThreshold.CRITICAL_ONLY.value,
            "max_templates": 10
        }
        
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-host",
                "port": 80,
                "module_configuration": custom_config
            },
        )
        
        nuclei = Nuclei()
        nuclei.process_task(task)
        
        # Verify the configuration was set correctly
        self.assertIsInstance(nuclei.configuration, NucleiConfiguration)
        self.assertEqual(nuclei.configuration.severity_threshold, SeverityThreshold.CRITICAL_ONLY)
        self.assertEqual(nuclei.configuration.max_templates, 10)

    def test_process_task_with_invalid_configuration(self) -> None:
        """Test that process_task falls back to defaults with invalid configuration."""
        invalid_config = {
            "enabled": "not a boolean",  # Invalid type
            "severity_threshold": "invalid_severity",  # Invalid severity
            "max_templates": -1  # Invalid value
        }
        
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-host",
                "port": 80,
                "module_configuration": invalid_config
            },
        )
        
        nuclei = Nuclei()
        nuclei.process_task(task)
        
        # Verify fallback to default configuration
        self.assertIsInstance(nuclei.configuration, NucleiConfiguration)
        self.assertEqual(nuclei.configuration.severity_threshold, Config.Modules.Nuclei.NUCLEI_SEVERITY_THRESHOLD)
        self.assertIsNone(nuclei.configuration.max_templates)

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

    def test_scan_with_max_templates(self) -> None:
        """Test that _scan respects max_templates configuration."""
        nuclei = Nuclei()
        nuclei.configuration = NucleiConfiguration(
            enabled=True,
            severity_threshold=SeverityThreshold.MEDIUM_AND_ABOVE,
            max_templates=2
        )
        
        templates = ["template1.yaml", "template2.yaml", "template3.yaml"]
        targets = ["http://example.com"]
        
        with patch('artemis.utils.check_output_log_on_error') as mock_check_output:
            mock_check_output.return_value = b""  # Mock empty response
            nuclei._scan(templates, targets)
            
            # Verify only first 2 templates were used
            for call_args in mock_check_output.call_args_list:
                command = call_args[0][0]
                if '-templates' in command:
                    templates_idx = command.index('-templates') + 1
                    used_templates = command[templates_idx].split(',')
                    self.assertEqual(len(used_templates), 2)
                    self.assertEqual(used_templates, ["template1.yaml", "template2.yaml"])

    def test_scan_with_severity_threshold(self) -> None:
        """Test that _scan applies severity threshold from configuration."""
        nuclei = Nuclei()
        nuclei.configuration = NucleiConfiguration(
            enabled=True,
            severity_threshold=SeverityThreshold.HIGH_AND_ABOVE,
            max_templates=None
        )
        
        templates = ["template1.yaml"]
        targets = ["http://example.com"]
        
        with patch('artemis.utils.check_output_log_on_error') as mock_check_output:
            mock_check_output.return_value = b""  # Mock empty response
            nuclei._scan(templates, targets)
            
            # Verify severity parameter was set correctly
            for call_args in mock_check_output.call_args_list:
                command = call_args[0][0]
                if '-s' in command:
                    severity_idx = command.index('-s') + 1
                    self.assertEqual(command[severity_idx], "critical,high")

    def test_scan_with_disabled_configuration(self) -> None:
        """Test that _scan handles disabled configuration correctly."""
        nuclei = Nuclei()
        nuclei.configuration = NucleiConfiguration(
            enabled=False,
            severity_threshold=SeverityThreshold.MEDIUM_AND_ABOVE,
            max_templates=None
        )
        
        templates = ["template1.yaml"]
        targets = ["http://example.com"]
        
        with patch('artemis.utils.check_output_log_on_error') as mock_check_output:
            mock_check_output.return_value = b""  # Mock empty response
            results = nuclei._scan(templates, targets)
            
            # Verify no scan was performed when disabled
            self.assertEqual(len(results), 0)
            mock_check_output.assert_not_called()

    def test_scan_with_no_configuration(self) -> None:
        """Test that _scan uses default configuration when none is provided."""
        nuclei = Nuclei()
        nuclei.configuration = None
        
        templates = ["template1.yaml"]
        targets = ["http://example.com"]
        
        with patch('artemis.utils.check_output_log_on_error') as mock_check_output:
            mock_check_output.return_value = b""  # Mock empty response
            nuclei._scan(templates, targets)
            
            # Verify default severity threshold was used
            for call_args in mock_check_output.call_args_list:
                command = call_args[0][0]
                if '-s' in command:
                    severity_idx = command.index('-s') + 1
                    expected_severity = SeverityThreshold.get_severity_list(Config.Modules.Nuclei.NUCLEI_SEVERITY_THRESHOLD)
                    self.assertEqual(command[severity_idx], ",".join(expected_severity))
