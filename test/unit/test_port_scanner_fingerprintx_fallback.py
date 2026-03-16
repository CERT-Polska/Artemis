import subprocess
import unittest
from socket import gethostbyname
from unittest.mock import MagicMock, call, patch

from artemis.modules.port_scanner import PortScanner


class TestPortScannerFingerprintxFallback(unittest.TestCase):
    """Unit tests for fingerprintx retry logic and HTTP fallback (mocked)."""

    def _make_scanner(self) -> MagicMock:
        scanner = MagicMock()
        scanner.cache.get.return_value = None
        scanner.requests_per_second_for_current_tasks = 0
        scanner.log = MagicMock()
        scanner.throttle_request = lambda f: f()
        return scanner

    def _mock_naabu(self, mock_popen: MagicMock, stdout: bytes) -> None:
        mock_process = MagicMock()
        mock_process.communicate.return_value = (stdout, b"")
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

    @patch("artemis.modules.port_scanner.time.sleep")
    @patch("artemis.modules.port_scanner.http_requests.request")
    @patch("artemis.modules.port_scanner.check_output_log_on_error")
    @patch("artemis.modules.port_scanner.subprocess.Popen")
    def test_retry_succeeds_on_second_attempt(
        self, mock_popen: MagicMock, mock_check_output: MagicMock, mock_http_request: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """When fingerprintx fails once then succeeds, the result should be used without HTTP fallback."""
        self._mock_naabu(mock_popen, b"10.0.0.1:22\n")
        mock_check_output.side_effect = [
            b"",  # attempt 1: empty
            b'{"port": 22, "tls": false, "protocol": "ssh", "version": "OpenSSH_8.9"}',  # attempt 2: success
        ]

        scanner = self._make_scanner()
        result = PortScanner._scan(scanner, ["10.0.0.1"])

        self.assertEqual(result["10.0.0.1"]["22"]["service"], "ssh")
        self.assertFalse(result["10.0.0.1"]["22"]["ssl"])
        mock_http_request.assert_not_called()
        self.assertEqual(mock_check_output.call_count, 2)

    @patch("artemis.modules.port_scanner.time.sleep")
    @patch("artemis.modules.port_scanner.http_requests.request")
    @patch("artemis.modules.port_scanner.check_output_log_on_error")
    @patch("artemis.modules.port_scanner.subprocess.Popen")
    def test_http_fallback_after_all_retries_exhausted(
        self, mock_popen: MagicMock, mock_check_output: MagicMock, mock_http_request: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """When all 3 fingerprintx retries return empty, HTTP fallback should detect HTTP services."""
        self._mock_naabu(mock_popen, b"10.0.0.1:8080\n")
        mock_check_output.return_value = b""  # all retries return empty
        mock_http_request.return_value = MagicMock(status_code=200)

        scanner = self._make_scanner()
        result = PortScanner._scan(scanner, ["10.0.0.1"])

        self.assertIn("10.0.0.1", result)
        self.assertIn("8080", result["10.0.0.1"])
        self.assertEqual(result["10.0.0.1"]["8080"]["service"], "http")
        self.assertEqual(mock_check_output.call_count, 3)

    @patch("artemis.modules.port_scanner.time.sleep")
    @patch("artemis.modules.port_scanner.http_requests.request")
    @patch("artemis.modules.port_scanner.check_output_log_on_error")
    @patch("artemis.modules.port_scanner.subprocess.Popen")
    def test_http_fallback_on_fingerprintx_exceptions(
        self, mock_popen: MagicMock, mock_check_output: MagicMock, mock_http_request: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """When fingerprintx raises CalledProcessError on all retries, HTTP fallback should be used."""
        self._mock_naabu(mock_popen, b"10.0.0.1:9090\n")
        mock_check_output.side_effect = subprocess.CalledProcessError(1, "fingerprintx")
        mock_http_request.return_value = MagicMock(status_code=200)

        scanner = self._make_scanner()
        result = PortScanner._scan(scanner, ["10.0.0.1"])

        self.assertIn("10.0.0.1", result)
        self.assertIn("9090", result["10.0.0.1"])
        self.assertEqual(result["10.0.0.1"]["9090"]["service"], "http")
        self.assertEqual(mock_check_output.call_count, 3)

    @patch("artemis.modules.port_scanner.time.sleep")
    @patch("artemis.modules.port_scanner.http_requests.request")
    @patch("artemis.modules.port_scanner.check_output_log_on_error")
    @patch("artemis.modules.port_scanner.subprocess.Popen")
    def test_https_detected_before_http(
        self, mock_popen: MagicMock, mock_check_output: MagicMock, mock_http_request: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """HTTPS should be tried first; if it succeeds, ssl should be True."""
        self._mock_naabu(mock_popen, b"10.0.0.1:8443\n")
        mock_check_output.return_value = b""
        mock_http_request.return_value = MagicMock(status_code=200)

        scanner = self._make_scanner()
        result = PortScanner._scan(scanner, ["10.0.0.1"])

        self.assertIn("8443", result["10.0.0.1"])
        self.assertTrue(result["10.0.0.1"]["8443"]["ssl"])
        self.assertEqual(result["10.0.0.1"]["8443"]["service"], "http")
        # First call should be https
        mock_http_request.assert_called_once_with("head", "https://10.0.0.1:8443/")

    @patch("artemis.modules.port_scanner.time.sleep")
    @patch("artemis.modules.port_scanner.http_requests.request")
    @patch("artemis.modules.port_scanner.check_output_log_on_error")
    @patch("artemis.modules.port_scanner.subprocess.Popen")
    def test_http_fallback_when_https_fails(
        self, mock_popen: MagicMock, mock_check_output: MagicMock, mock_http_request: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """When HTTPS probe fails but HTTP succeeds, ssl should be False."""
        self._mock_naabu(mock_popen, b"10.0.0.1:8080\n")
        mock_check_output.return_value = b""
        mock_http_request.side_effect = [
            ConnectionError("SSL failed"),  # https fails
            MagicMock(status_code=200),  # http succeeds
        ]

        scanner = self._make_scanner()
        result = PortScanner._scan(scanner, ["10.0.0.1"])

        self.assertIn("8080", result["10.0.0.1"])
        self.assertFalse(result["10.0.0.1"]["8080"]["ssl"])
        self.assertEqual(mock_http_request.call_count, 2)

    @patch("artemis.modules.port_scanner.time.sleep")
    @patch("artemis.modules.port_scanner.http_requests.request")
    @patch("artemis.modules.port_scanner.check_output_log_on_error")
    @patch("artemis.modules.port_scanner.subprocess.Popen")
    def test_port_skipped_when_all_methods_fail(
        self, mock_popen: MagicMock, mock_check_output: MagicMock, mock_http_request: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """When fingerprintx retries and HTTP probes all fail, port should be skipped."""
        self._mock_naabu(mock_popen, b"10.0.0.1:6379\n")
        mock_check_output.return_value = b""
        mock_http_request.side_effect = ConnectionError("refused")

        scanner = self._make_scanner()
        result = PortScanner._scan(scanner, ["10.0.0.1"])

        self.assertEqual(result.get("10.0.0.1", {}), {})
        self.assertEqual(mock_check_output.call_count, 3)

    @patch("artemis.modules.port_scanner.time.sleep")
    @patch("artemis.modules.port_scanner.http_requests.request")
    @patch("artemis.modules.port_scanner.check_output_log_on_error")
    @patch("artemis.modules.port_scanner.subprocess.Popen")
    def test_fingerprintx_success_no_fallback(
        self, mock_popen: MagicMock, mock_check_output: MagicMock, mock_http_request: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """When fingerprintx succeeds on first try, no retry or fallback should occur."""
        self._mock_naabu(mock_popen, b"10.0.0.1:22\n")
        mock_check_output.return_value = b'{"port": 22, "tls": false, "protocol": "ssh", "version": "OpenSSH_8.9"}'

        scanner = self._make_scanner()
        result = PortScanner._scan(scanner, ["10.0.0.1"])

        self.assertEqual(result["10.0.0.1"]["22"]["service"], "ssh")
        self.assertFalse(result["10.0.0.1"]["22"]["ssl"])
        mock_http_request.assert_not_called()
        mock_sleep.assert_not_called()
        self.assertEqual(mock_check_output.call_count, 1)


class TestPortScannerFingerprintxFallbackIntegration(unittest.TestCase):
    """Integration tests using a real HTTP target (test-nginx from docker-compose.test.yaml).

    These tests exercise the HTTP fallback against a live service to verify
    the retry and fallback logic works end-to-end, not just with mocks.
    Fingerprintx is still mocked to simulate failure, but the HTTP fallback
    hits the real nginx instance.
    """

    def _make_scanner(self) -> MagicMock:
        scanner = MagicMock()
        scanner.cache.get.return_value = None
        scanner.requests_per_second_for_current_tasks = 0
        scanner.log = MagicMock()
        scanner.throttle_request = lambda f: f()
        return scanner

    def _mock_naabu(self, mock_popen: MagicMock, stdout: bytes) -> None:
        mock_process = MagicMock()
        mock_process.communicate.return_value = (stdout, b"")
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

    @patch("artemis.modules.port_scanner.time.sleep")
    @patch("artemis.modules.port_scanner.check_output_log_on_error")
    @patch("artemis.modules.port_scanner.subprocess.Popen")
    def test_http_fallback_against_real_nginx(
        self, mock_popen: MagicMock, mock_check_output: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """With fingerprintx failing, the HTTP fallback should detect a real nginx service."""
        nginx_ip = gethostbyname("test-nginx")
        self._mock_naabu(mock_popen, f"{nginx_ip}:80\n".encode())
        mock_check_output.return_value = b""  # simulate fingerprintx returning nothing

        scanner = self._make_scanner()
        result = PortScanner._scan(scanner, [nginx_ip])

        self.assertIn(nginx_ip, result)
        self.assertIn("80", result[nginx_ip])
        self.assertEqual(result[nginx_ip]["80"]["service"], "http")
        # nginx on port 80 is plain HTTP, so https probe should fail and http should succeed
        self.assertFalse(result[nginx_ip]["80"]["ssl"])
        self.assertEqual(mock_check_output.call_count, 3)

    @patch("artemis.modules.port_scanner.time.sleep")
    @patch("artemis.modules.port_scanner.check_output_log_on_error")
    @patch("artemis.modules.port_scanner.subprocess.Popen")
    def test_retry_then_fallback_against_real_nginx(
        self, mock_popen: MagicMock, mock_check_output: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """Fingerprintx raises exceptions on all retries, then HTTP fallback hits real nginx."""
        nginx_ip = gethostbyname("test-nginx")
        self._mock_naabu(mock_popen, f"{nginx_ip}:80\n".encode())
        mock_check_output.side_effect = subprocess.CalledProcessError(1, "fingerprintx")

        scanner = self._make_scanner()
        result = PortScanner._scan(scanner, [nginx_ip])

        self.assertIn(nginx_ip, result)
        self.assertIn("80", result[nginx_ip])
        self.assertEqual(result[nginx_ip]["80"]["service"], "http")
        self.assertFalse(result[nginx_ip]["80"]["ssl"])
        self.assertEqual(mock_check_output.call_count, 3)

    @patch("artemis.modules.port_scanner.time.sleep")
    @patch("artemis.modules.port_scanner.check_output_log_on_error")
    @patch("artemis.modules.port_scanner.subprocess.Popen")
    def test_non_http_port_skipped_after_fallback(
        self, mock_popen: MagicMock, mock_check_output: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """A port with no HTTP service should be skipped after retries and fallback both fail."""
        nginx_ip = gethostbyname("test-nginx")
        # Use a port that nginx is NOT listening on — fallback should fail
        self._mock_naabu(mock_popen, f"{nginx_ip}:12345\n".encode())
        mock_check_output.return_value = b""

        scanner = self._make_scanner()
        result = PortScanner._scan(scanner, [nginx_ip])

        # Port 12345 is not open, so both https and http fallback should fail
        self.assertEqual(result.get(nginx_ip, {}), {})
        self.assertEqual(mock_check_output.call_count, 3)
