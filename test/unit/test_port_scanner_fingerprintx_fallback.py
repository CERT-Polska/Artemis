import subprocess
import unittest
from unittest.mock import MagicMock, patch

import requests

from artemis.modules.port_scanner import PortScanner


class TestPortScannerFingerprintxFallback(unittest.TestCase):
    """Tests for fingerprintx retry logic and HTTP fallback."""

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
    @patch("artemis.modules.port_scanner.requests.head")
    @patch("artemis.modules.port_scanner.check_output_log_on_error")
    @patch("artemis.modules.port_scanner.subprocess.Popen")
    def test_retry_succeeds_on_second_attempt(
        self, mock_popen: MagicMock, mock_check_output: MagicMock, mock_head: MagicMock, mock_sleep: MagicMock
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
        mock_head.assert_not_called()
        self.assertEqual(mock_check_output.call_count, 2)

    @patch("artemis.modules.port_scanner.time.sleep")
    @patch("artemis.modules.port_scanner.requests.head")
    @patch("artemis.modules.port_scanner.check_output_log_on_error")
    @patch("artemis.modules.port_scanner.subprocess.Popen")
    def test_http_fallback_after_all_retries_exhausted(
        self, mock_popen: MagicMock, mock_check_output: MagicMock, mock_head: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """When all 3 fingerprintx retries return empty, HTTP fallback should detect HTTP services."""
        self._mock_naabu(mock_popen, b"10.0.0.1:8080\n")
        mock_check_output.return_value = b""  # all retries return empty
        mock_head.return_value = MagicMock(status_code=200)

        scanner = self._make_scanner()
        result = PortScanner._scan(scanner, ["10.0.0.1"])

        self.assertIn("10.0.0.1", result)
        self.assertIn("8080", result["10.0.0.1"])
        self.assertEqual(result["10.0.0.1"]["8080"]["service"], "http")
        self.assertEqual(mock_check_output.call_count, 3)

    @patch("artemis.modules.port_scanner.time.sleep")
    @patch("artemis.modules.port_scanner.requests.head")
    @patch("artemis.modules.port_scanner.check_output_log_on_error")
    @patch("artemis.modules.port_scanner.subprocess.Popen")
    def test_http_fallback_on_fingerprintx_exceptions(
        self, mock_popen: MagicMock, mock_check_output: MagicMock, mock_head: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """When fingerprintx raises CalledProcessError on all retries, HTTP fallback should be used."""
        self._mock_naabu(mock_popen, b"10.0.0.1:9090\n")
        mock_check_output.side_effect = subprocess.CalledProcessError(1, "fingerprintx")
        mock_head.return_value = MagicMock(status_code=200)

        scanner = self._make_scanner()
        result = PortScanner._scan(scanner, ["10.0.0.1"])

        self.assertIn("10.0.0.1", result)
        self.assertIn("9090", result["10.0.0.1"])
        self.assertEqual(result["10.0.0.1"]["9090"]["service"], "http")
        self.assertEqual(mock_check_output.call_count, 3)

    @patch("artemis.modules.port_scanner.time.sleep")
    @patch("artemis.modules.port_scanner.requests.head")
    @patch("artemis.modules.port_scanner.check_output_log_on_error")
    @patch("artemis.modules.port_scanner.subprocess.Popen")
    def test_https_detected_before_http(
        self, mock_popen: MagicMock, mock_check_output: MagicMock, mock_head: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """HTTPS should be tried first; if it succeeds, ssl should be True."""
        self._mock_naabu(mock_popen, b"10.0.0.1:8443\n")
        mock_check_output.return_value = b""
        mock_head.return_value = MagicMock(status_code=200)

        scanner = self._make_scanner()
        result = PortScanner._scan(scanner, ["10.0.0.1"])

        self.assertIn("8443", result["10.0.0.1"])
        self.assertTrue(result["10.0.0.1"]["8443"]["ssl"])
        self.assertEqual(result["10.0.0.1"]["8443"]["service"], "http")

    @patch("artemis.modules.port_scanner.time.sleep")
    @patch("artemis.modules.port_scanner.requests.head")
    @patch("artemis.modules.port_scanner.check_output_log_on_error")
    @patch("artemis.modules.port_scanner.subprocess.Popen")
    def test_http_fallback_when_https_fails(
        self, mock_popen: MagicMock, mock_check_output: MagicMock, mock_head: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """When HTTPS probe fails but HTTP succeeds, ssl should be False."""
        self._mock_naabu(mock_popen, b"10.0.0.1:8080\n")
        mock_check_output.return_value = b""
        mock_head.side_effect = [
            requests.ConnectionError("SSL failed"),  # https fails
            MagicMock(status_code=200),  # http succeeds
        ]

        scanner = self._make_scanner()
        result = PortScanner._scan(scanner, ["10.0.0.1"])

        self.assertIn("8080", result["10.0.0.1"])
        self.assertFalse(result["10.0.0.1"]["8080"]["ssl"])

    @patch("artemis.modules.port_scanner.time.sleep")
    @patch("artemis.modules.port_scanner.requests.head")
    @patch("artemis.modules.port_scanner.check_output_log_on_error")
    @patch("artemis.modules.port_scanner.subprocess.Popen")
    def test_port_skipped_when_all_methods_fail(
        self, mock_popen: MagicMock, mock_check_output: MagicMock, mock_head: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """When fingerprintx retries and HTTP probes all fail, port should be skipped."""
        self._mock_naabu(mock_popen, b"10.0.0.1:6379\n")
        mock_check_output.return_value = b""
        mock_head.side_effect = requests.ConnectionError("refused")

        scanner = self._make_scanner()
        result = PortScanner._scan(scanner, ["10.0.0.1"])

        self.assertEqual(result.get("10.0.0.1", {}), {})
        self.assertEqual(mock_check_output.call_count, 3)

    @patch("artemis.modules.port_scanner.time.sleep")
    @patch("artemis.modules.port_scanner.requests.head")
    @patch("artemis.modules.port_scanner.check_output_log_on_error")
    @patch("artemis.modules.port_scanner.subprocess.Popen")
    def test_fingerprintx_success_no_fallback(
        self, mock_popen: MagicMock, mock_check_output: MagicMock, mock_head: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """When fingerprintx succeeds on first try, no retry or fallback should occur."""
        self._mock_naabu(mock_popen, b"10.0.0.1:22\n")
        mock_check_output.return_value = b'{"port": 22, "tls": false, "protocol": "ssh", "version": "OpenSSH_8.9"}'

        scanner = self._make_scanner()
        result = PortScanner._scan(scanner, ["10.0.0.1"])

        self.assertEqual(result["10.0.0.1"]["22"]["service"], "ssh")
        self.assertFalse(result["10.0.0.1"]["22"]["ssl"])
        mock_head.assert_not_called()
        mock_sleep.assert_not_called()
        self.assertEqual(mock_check_output.call_count, 1)
