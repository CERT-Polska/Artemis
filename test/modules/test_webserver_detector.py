from test.base import ArtemisModuleTestCase
from unittest.mock import MagicMock, patch

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.webserver_detector import WebServerDetector


class WebServerDetectorTest(ArtemisModuleTestCase):
    karton_class = WebServerDetector  # type: ignore

    @patch("artemis.module_base.ArtemisBase.http_get")
    def test_nginx_detection(self, mock_http_get: MagicMock) -> None:
        """Test Nginx detection from Server header"""
        mock_response = MagicMock()
        mock_response.headers = {"Server": "nginx/1.18.0"}
        mock_http_get.return_value = mock_response

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("nginx/1.18.0", call.kwargs["status_reason"])
        self.assertEqual(call.kwargs["data"]["server"]["name"], "nginx")
        self.assertEqual(call.kwargs["data"]["server"]["version"], "1.18.0")

    @patch("artemis.module_base.ArtemisBase.http_get")
    def test_apache_detection(self, mock_http_get: MagicMock) -> None:
        """Test Apache detection from Server header"""
        mock_response = MagicMock()
        mock_response.headers = {"Server": "Apache/2.4.41 (Ubuntu)"}
        mock_http_get.return_value = mock_response

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("Apache/2.4.41", call.kwargs["status_reason"])
        self.assertEqual(call.kwargs["data"]["server"]["name"], "Apache")
        self.assertEqual(call.kwargs["data"]["server"]["version"], "2.4.41")

    @patch("artemis.module_base.ArtemisBase.http_get")
    def test_iis_detection(self, mock_http_get: MagicMock) -> None:
        """Test IIS detection from Server header"""
        mock_response = MagicMock()
        mock_response.headers = {"Server": "Microsoft-IIS/10.0"}
        mock_http_get.return_value = mock_response

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("Microsoft-IIS/10.0", call.kwargs["status_reason"])
        self.assertEqual(call.kwargs["data"]["server"]["name"], "Microsoft-IIS")
        self.assertEqual(call.kwargs["data"]["server"]["version"], "10.0")

    @patch("artemis.module_base.ArtemisBase.http_get")
    def test_lighttpd_detection(self, mock_http_get: MagicMock) -> None:
        """Test lighttpd detection from Server header"""
        mock_response = MagicMock()
        mock_response.headers = {"Server": "lighttpd/1.4.55"}
        mock_http_get.return_value = mock_response

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["data"]["server"]["name"], "lighttpd")
        self.assertEqual(call.kwargs["data"]["server"]["version"], "1.4.55")

    @patch("artemis.module_base.ArtemisBase.http_get")
    def test_no_server_header(self, mock_http_get: MagicMock) -> None:
        """Test when Server header is missing"""
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_http_get.return_value = mock_response

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
        self.assertIn("No web server information detected", call.kwargs["status_reason"])
        self.assertIsNone(call.kwargs["data"]["server"])

    @patch("artemis.module_base.ArtemisBase.http_get")
    def test_obfuscated_server_header(self, mock_http_get: MagicMock) -> None:
        """Test obfuscated/custom Server header"""
        mock_response = MagicMock()
        mock_response.headers = {"Server": "CustomServer"}
        mock_http_get.return_value = mock_response

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["data"]["server"]["name"], "CustomServer")
        self.assertIsNone(call.kwargs["data"]["server"]["version"])

    @patch("artemis.module_base.ArtemisBase.http_get")
    def test_complex_server_header(self, mock_http_get: MagicMock) -> None:
        """Test complex Server header with multiple components"""
        mock_response = MagicMock()
        mock_response.headers = {"Server": "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f"}
        mock_http_get.return_value = mock_response

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["data"]["server"]["name"], "Apache")
        self.assertEqual(call.kwargs["data"]["server"]["version"], "2.4.41")

    @patch("artemis.module_base.ArtemisBase.http_get")
    def test_version_extraction(self, mock_http_get: MagicMock) -> None:
        """Test version number extraction with various formats"""
        test_cases = [
            ("nginx/1.18.0", "nginx", "1.18.0"),
            ("Apache/2.4.41", "Apache", "2.4.41"),
            ("Microsoft-IIS/10.0", "Microsoft-IIS", "10.0"),
            ("CustomServer", "CustomServer", None),
            ("nginx", "nginx", None),
        ]

        for header_value, expected_name, expected_version in test_cases:
            mock_response = MagicMock()
            mock_response.headers = {"Server": header_value}
            mock_http_get.return_value = mock_response

            result = self.karton._detect_webserver(mock_response)
            self.assertEqual(result["name"], expected_name)
            if expected_version:
                self.assertEqual(result["version"], expected_version)
            else:
                self.assertIsNone(result.get("version"))
