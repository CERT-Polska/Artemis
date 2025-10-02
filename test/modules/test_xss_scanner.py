"""Tests for XSS Scanner module."""
# type: ignore
from test.base import ArtemisModuleTestCase
from unittest.mock import MagicMock, patch

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.http_requests import HTTPResponse
from artemis.modules.xss_scanner import XSSScanner, XSSFindings


class XSSScannerTestCase(ArtemisModuleTestCase):
    """Test cases for XSS Scanner module."""

    karton_class = XSSScanner

    @patch("artemis.modules.xss_scanner.get_links_and_resources_on_same_domain")
    def test_xss_basic_payload_detection(self, mock_get_links: MagicMock) -> None:
        """Test detection of basic XSS payload reflection."""
        mock_get_links.return_value = []

        # Mock HTTP responses
        safe_response = MagicMock(spec=HTTPResponse)
        safe_response.content = "<html><body>Hello World</body></html>"

        vulnerable_response = MagicMock(spec=HTTPResponse)
        vulnerable_response.content = "<html><body>Hello <script>alert(1)</script></body></html>"

        with patch.object(self.karton, "http_get") as mock_http_get:
            mock_http_get.side_effect = [safe_response, vulnerable_response]

            task = Task(
                {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
                payload={"host": "test-xss.example.com", "port": 80},
            )
            self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("XSS", call.kwargs["status_reason"])

        result_data = call.kwargs["data"]["result"]
        self.assertGreater(len(result_data), 0)
        self.assertEqual(result_data[0]["code"], XSSFindings.XSS_VULNERABILITY.value)

    @patch("artemis.modules.xss_scanner.get_links_and_resources_on_same_domain")
    def test_xss_encoded_payload_detection(self, mock_get_links: MagicMock) -> None:
        """Test detection of HTML entity encoded XSS payloads."""
        mock_get_links.return_value = []

        safe_response = MagicMock(spec=HTTPResponse)
        safe_response.content = "<html><body>Safe content</body></html>"

        # Response with HTML entity encoded payload
        vulnerable_response = MagicMock(spec=HTTPResponse)
        vulnerable_response.content = "<html><body><script>alert(&#49;)</script></body></html>"

        with patch.object(self.karton, "http_get") as mock_http_get:
            mock_http_get.side_effect = [safe_response, vulnerable_response]

            task = Task(
                {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
                payload={"host": "test-xss-encoded.example.com", "port": 80},
            )
            self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

        result_data = call.kwargs["data"]["result"]
        self.assertGreater(len(result_data), 0)

    @patch("artemis.modules.xss_scanner.get_links_and_resources_on_same_domain")
    def test_xss_event_handler_detection(self, mock_get_links: MagicMock) -> None:
        """Test detection of event handler-based XSS."""
        mock_get_links.return_value = []

        safe_response = MagicMock(spec=HTTPResponse)
        safe_response.content = "<html><body>Normal page</body></html>"

        vulnerable_response = MagicMock(spec=HTTPResponse)
        vulnerable_response.content = "<html><body><img src=x onerror=alert(1)></body></html>"

        with patch.object(self.karton, "http_get") as mock_http_get:
            mock_http_get.side_effect = [safe_response, vulnerable_response]

            task = Task(
                {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
                payload={"host": "test-xss-event.example.com", "port": 80},
            )
            self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

    @patch("artemis.modules.xss_scanner.get_links_and_resources_on_same_domain")
    def test_xss_svg_payload_detection(self, mock_get_links: MagicMock) -> None:
        """Test detection of SVG-based XSS."""
        mock_get_links.return_value = []

        safe_response = MagicMock(spec=HTTPResponse)
        safe_response.content = "<html><body>Clean page</body></html>"

        vulnerable_response = MagicMock(spec=HTTPResponse)
        vulnerable_response.content = "<html><body><svg/onload=alert(1)></body></html>"

        with patch.object(self.karton, "http_get") as mock_http_get:
            mock_http_get.side_effect = [safe_response, vulnerable_response]

            task = Task(
                {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
                payload={"host": "test-xss-svg.example.com", "port": 80},
            )
            self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

    @patch("artemis.modules.xss_scanner.get_links_and_resources_on_same_domain")
    def test_xss_no_false_positive(self, mock_get_links: MagicMock) -> None:
        """Test that safe pages don't trigger false positives."""
        mock_get_links.return_value = []

        safe_response = MagicMock(spec=HTTPResponse)
        safe_response.content = "<html><body>This is a completely safe page with no vulnerabilities</body></html>"

        with patch.object(self.karton, "http_get") as mock_http_get:
            mock_http_get.return_value = safe_response

            task = Task(
                {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
                payload={"host": "safe-site.example.com", "port": 80},
            )
            self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
        self.assertIsNone(call.kwargs["status_reason"])

    @patch("artemis.modules.xss_scanner.get_links_and_resources_on_same_domain")
    def test_xss_javascript_uri_detection(self, mock_get_links: MagicMock) -> None:
        """Test detection of javascript: URI scheme XSS."""
        mock_get_links.return_value = []

        safe_response = MagicMock(spec=HTTPResponse)
        safe_response.content = "<html><body>Normal content</body></html>"

        vulnerable_response = MagicMock(spec=HTTPResponse)
        vulnerable_response.content = '<html><body><a href="javascript:alert(1)">click</a></body></html>'

        with patch.object(self.karton, "http_get") as mock_http_get:
            mock_http_get.side_effect = [safe_response, vulnerable_response]

            task = Task(
                {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
                payload={"host": "test-xss-uri.example.com", "port": 80},
            )
            self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

    @patch("artemis.modules.xss_scanner.get_links_and_resources_on_same_domain")
    def test_xss_payload_reflection(self, mock_get_links: MagicMock) -> None:
        """Test detection of reflected payload in response."""
        mock_get_links.return_value = []

        safe_response = MagicMock(spec=HTTPResponse)
        safe_response.content = "<html><body>Search results for: </body></html>"

        # Payload is reflected but not executed (still vulnerable)
        reflected_response = MagicMock(spec=HTTPResponse)
        reflected_response.content = "<html><body>Search results for: <script>alert(1)</script></body></html>"

        with patch.object(self.karton, "http_get") as mock_http_get:
            mock_http_get.side_effect = [safe_response, reflected_response]

            task = Task(
                {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
                payload={"host": "test-xss-reflect.example.com", "port": 80},
            )
            self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

        result_data = call.kwargs["data"]["result"]
        self.assertGreater(len(result_data), 0)
        # Check that payload reflection was detected
        self.assertIn("Payload reflected", result_data[0]["matched_indicator"])

    @patch("artemis.modules.xss_scanner.get_links_and_resources_on_same_domain")
    def test_xss_url_with_existing_params(self, mock_get_links: MagicMock) -> None:
        """Test XSS detection on URLs that already have parameters."""
        mock_get_links.return_value = []

        safe_response = MagicMock(spec=HTTPResponse)
        safe_response.content = "<html><body>Page content</body></html>"

        vulnerable_response = MagicMock(spec=HTTPResponse)
        vulnerable_response.content = "<html><body><script>alert(1)</script></body></html>"

        with patch.object(self.karton, "http_get") as mock_http_get:
            # First call is for base URL, subsequent for payloads
            mock_http_get.side_effect = [safe_response, vulnerable_response]

            task = Task(
                {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
                payload={"host": "test-xss.example.com", "port": 80},
            )
            self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

    def test_strip_query_string(self) -> None:
        """Test query string removal utility function."""
        scanner = self.karton
        url = "http://example.com/page?param=value&foo=bar#fragment"
        stripped = scanner._strip_query_string(url)
        self.assertEqual(stripped, "http://example.com/page")

    def test_is_url_with_parameters(self) -> None:
        """Test URL parameter detection utility function."""
        scanner = self.karton
        self.assertTrue(scanner.is_url_with_parameters("http://example.com/page?param=value"))
        self.assertFalse(scanner.is_url_with_parameters("http://example.com/page"))
        self.assertTrue(scanner.is_url_with_parameters("http://example.com/page?foo=bar&baz=qux"))

    def test_create_url_with_batch_payload(self) -> None:
        """Test URL creation with payload injection."""
        scanner = self.karton
        url = "http://example.com/page"
        params = ["q", "search"]
        payload = "<script>alert(1)</script>"

        result = scanner.create_url_with_batch_payload(url, params, payload)

        # Check that URL has query params
        self.assertIn("?", result)
        # Check that both params are present
        self.assertIn("q=", result)
        self.assertIn("search=", result)
        # Payload should be URL encoded
        self.assertIn("%3Cscript%3E", result)
