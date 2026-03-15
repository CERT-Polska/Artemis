import subprocess
import unittest
from unittest.mock import MagicMock, patch

from artemis.modules.port_scanner import PortScanner


class TestPortScannerNaabuFailure(unittest.TestCase):
    @patch("artemis.modules.port_scanner.subprocess.Popen")
    def test_scan_raises_on_naabu_failure(self, mock_popen: MagicMock) -> None:
        """Verify that _scan raises CalledProcessError when naabu exits non-zero."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b"", b"naabu failed")
        mock_process.returncode = 1
        mock_popen.return_value = mock_process

        scanner = MagicMock()
        scanner.cache.get.return_value = None
        scanner.requests_per_second_for_current_tasks = 0

        with self.assertRaises(subprocess.CalledProcessError) as ctx:
            PortScanner._scan(scanner, ["127.0.0.1"])

        self.assertEqual(ctx.exception.returncode, 1)
        self.assertEqual(ctx.exception.stderr, b"naabu failed")
