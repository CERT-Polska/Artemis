import subprocess
from unittest.mock import MagicMock

import pytest

from artemis.modules.port_scanner import PortScanner


def test_scan_raises_on_naabu_failure(monkeypatch):
    """Verify that _scan raises CalledProcessError when naabu exits non-zero."""
    mock_process = MagicMock()
    mock_process.communicate.return_value = (b"", b"naabu failed")
    mock_process.returncode = 1

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: mock_process)

    scanner = MagicMock()
    scanner.cache.get.return_value = None
    scanner.log = MagicMock()
    scanner.requests_per_second_for_current_tasks = 0

    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        PortScanner._scan(scanner, ["127.0.0.1"])

    assert exc_info.value.returncode == 1
    assert exc_info.value.stderr == b"naabu failed"
