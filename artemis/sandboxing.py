import os
import subprocess
from typing import Dict, List, Optional

SANDBOX_WRAPPER = "/sandbox.sh"


def run_sandboxed(args: List[str], timeout: int = 60, env: Optional[Dict[str, str]] = None) -> bytes:
    return subprocess.check_output(
        [SANDBOX_WRAPPER] + args,
        env={**os.environ, **(env or {})},
        stderr=subprocess.DEVNULL,
        timeout=timeout,
    )


def assert_sandboxed() -> None:
    """
    Empirically ensure that the process is Landlocked.
    TODO: add networking checks here
    """
    try:
        fd = os.open("/.sandbox-probe", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        os.unlink("/.sandbox-probe")
    except PermissionError:
        return
    raise RuntimeError("Not running under the sandbox - refusing to proceed, see docker/sandbox.sh")
