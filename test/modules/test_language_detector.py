from test.base import ArtemisModuleTestCase
from unittest.mock import MagicMock, patch

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.language_detector import LanguageDetector


class LanguageDetectorTest(ArtemisModuleTestCase):
    karton_class = LanguageDetector  # type: ignore

    @patch("artemis.module_base.ArtemisBase.http_get")
    def test_php_detection_from_x_powered_by(self, mock_http_get: MagicMock) -> None:
        """Test PHP version detection from X-Powered-By header"""
        mock_response = MagicMock()
        mock_response.headers = {"X-Powered-By": "PHP/7.4.3"}
        mock_http_get.return_value = mock_response

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("PHP/7.4.3", call.kwargs["status_reason"])
        self.assertEqual(call.kwargs["data"]["languages"][0]["name"], "PHP")
        self.assertEqual(call.kwargs["data"]["languages"][0]["version"], "7.4.3")

    @patch("artemis.module_base.ArtemisBase.http_get")
    def test_aspnet_detection(self, mock_http_get: MagicMock) -> None:
        """Test ASP.NET detection from X-Powered-By header"""
        mock_response = MagicMock()
        mock_response.headers = {"X-Powered-By": "ASP.NET"}
        mock_http_get.return_value = mock_response

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("ASP.NET", call.kwargs["status_reason"])
        self.assertEqual(call.kwargs["data"]["languages"][0]["name"], "ASP.NET")

    @patch("artemis.module_base.ArtemisBase.http_get")
    def test_multiple_languages(self, mock_http_get: MagicMock) -> None:
        """Test detection of multiple languages"""
        mock_response = MagicMock()
        mock_response.headers = {
            "X-Powered-By": "PHP/8.1.0",
            "Server": "Apache/2.4.41 (Ubuntu) mod_wsgi/4.7.1 Python/3.8.10",
        }
        mock_http_get.return_value = mock_response

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(len(call.kwargs["data"]["languages"]), 2)

    @patch("artemis.module_base.ArtemisBase.http_get")
    def test_no_language_detected(self, mock_http_get: MagicMock) -> None:
        """Test when no programming language is detected"""
        mock_response = MagicMock()
        mock_response.headers = {"Server": "nginx/1.18.0"}
        mock_http_get.return_value = mock_response

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
        self.assertIn("No programming languages detected", call.kwargs["status_reason"])
        self.assertEqual(call.kwargs["data"]["languages"], [])

    @patch("artemis.module_base.ArtemisBase.http_get")
    def test_python_detection_from_server_header(self, mock_http_get: MagicMock) -> None:
        """Test Python detection from Server header"""
        mock_response = MagicMock()
        mock_response.headers = {"Server": "nginx/1.18.0 mod_wsgi/4.7.1 Python/3.9.5"}
        mock_http_get.return_value = mock_response

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("Python/3.9.5", call.kwargs["status_reason"])
        self.assertEqual(call.kwargs["data"]["languages"][0]["name"], "Python")
        self.assertEqual(call.kwargs["data"]["languages"][0]["version"], "3.9.5")

    @patch("artemis.module_base.ArtemisBase.http_get")
    def test_perl_detection(self, mock_http_get: MagicMock) -> None:
        """Test Perl detection from Server header"""
        mock_response = MagicMock()
        mock_response.headers = {"Server": "Apache/2.4.41 mod_perl/2.0.11 Perl/5.30.0"}
        mock_http_get.return_value = mock_response

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertTrue(any(lang["name"] == "Perl" for lang in call.kwargs["data"]["languages"]))

    @patch("artemis.module_base.ArtemisBase.http_get")
    def test_version_extraction(self, mock_http_get: MagicMock) -> None:
        """Test version number extraction with various formats"""
        test_cases = [
            ("PHP/7.4.3", "PHP", "7.4.3"),
            ("PHP/8.1.0-dev", "PHP", "8.1.0-dev"),
            ("Python/3.9.5", "Python", "3.9.5"),
            ("ASP.NET", "ASP.NET", None),
        ]

        for header_value, expected_name, expected_version in test_cases:
            mock_response = MagicMock()
            mock_response.headers = {"X-Powered-By": header_value}
            mock_http_get.return_value = mock_response

            result = self.karton._detect_languages(mock_response)
            self.assertEqual(result[0]["name"], expected_name)
            if expected_version:
                self.assertEqual(result[0]["version"], expected_version)
