"""
Landlock-based sandbox (landrun, https://github.com/zouuup/landrun)

TODO: restrict TCP egress on per-domain basis
TODO: Landlock can't restrict UDP egress on kernel <7.2, block it at iptables level
TODO: check if io_uring is a problem for this sandboxing.
"""

import ctypes
import os
import shutil
import subprocess
import tempfile
from enum import Enum, auto
from typing import Dict, List, Optional

# The scratch dir location is exposed to the sandboxed process under this environment variable
# name (sandbox_checks.sh relies on it, too).
SANDBOX_TMP = "SANDBOX_TMP"
# Placeholder in landrun_args, substituted by run_sandboxed with the location of the run's
# scratch dir (a fresh temp dir under /tmp).
SCRATCH_DIR = "{scratch_dir}"
# The sandbox checks (one sh function per check, grouped per level), run inside landrun by the
# test suite. They live in artemis/sandboxing_payloads, together with the other code that is only
# ever run inside landrun.
SANDBOX_CHECKS_SH = os.path.join(os.path.dirname(__file__), "sandboxing_payloads", "sandbox_checks.sh")


class SandboxProfile(Enum):
    LV_STRICT = auto()
    LV_VCS = auto()
    LV_PYTHON = auto()
    LV_INTERNET = auto()

    @property
    def landrun_args(self) -> List[str]:
        if self is SandboxProfile.LV_STRICT:
            return ["--rox", "/bin/,/usr/bin/,/lib"]
        if self is SandboxProfile.LV_VCS:
            return [
                "--rox",
                "/usr/bin/git,/bin,/usr/bin,/usr/lib,/lib",
                "--ro",
                "/etc",
                "--rw",
                f"/dev/null,{SCRATCH_DIR}",
                "--env",
                f"{SANDBOX_TMP}={SCRATCH_DIR}",
            ]
        if self is SandboxProfile.LV_PYTHON:
            return [
                "--rox",
                "/usr/local/bin/python3,/bin,/usr/bin,/usr/local/lib,/usr/lib,/lib",
                "--ro",
                "/opt",
                "--rw",
                SCRATCH_DIR,
                "--env",
                f"{SANDBOX_TMP}={SCRATCH_DIR}",
                # redirect the bytecode cache of the read-only /opt module code into the scratch dir
                "--env",
                f"PYTHONPYCACHEPREFIX={SCRATCH_DIR}",
            ]
        if self is SandboxProfile.LV_INTERNET:
            return [
                "--rox",
                "/usr,/bin,/sbin,/lib",
                "--ro",
                "/opt,/etc",
                "--rw",
                f"/dev/null,{SCRATCH_DIR}",
                "--connect-tcp",
                "80,443",
                "--env",
                f"{SANDBOX_TMP}={SCRATCH_DIR}",
            ]

        assert False


# Network confinement needs Landlock ABI 4 (kernel >=6.7) - checked to fail fast instead of
# silently not enforcing the port allowlist. syscall 444 is LANDLOCK_CREATE_RULESET_VERSION.
def _assert_landlock_abi() -> None:
    libc = ctypes.CDLL(None)
    libc.syscall.restype = ctypes.c_long
    abi = libc.syscall(444, None, 0, 1)
    if abi < 4:
        raise RuntimeError(f"Landlock ABI {abi} is too old, network confinement needs kernel >=6.7")


def run_sandboxed(
    args: List[str],
    profile: SandboxProfile,
    timeout: int = 60,
    env: Optional[Dict[str, str]] = None,
    sandbox_paths: Optional[List[str]] = None,
) -> bytes:
    # TODO: ensure that calling .decode() is safe in Python.
    _assert_landlock_abi()
    # Every run gets a fresh scratch dir: the host paths in sandbox_paths are copied into it (the
    # sandboxed process never touches host paths directly) and its location substitutes the
    # SCRATCH_DIR placeholder in the landrun arguments. Arguments equal to a listed path are
    # rewritten to the copy.
    with tempfile.TemporaryDirectory() as scratch_dir:
        command = ["landrun", "--ro", os.path.dirname(SANDBOX_CHECKS_SH), *profile.landrun_args]
        for path in sandbox_paths or []:
            destination = os.path.join(scratch_dir, os.path.basename(path))
            if os.path.isdir(path):
                shutil.copytree(path, destination)
            else:
                shutil.copy2(path, destination)
            args = [destination if arg == path else arg for arg in args]
        command = [arg.replace(SCRATCH_DIR, scratch_dir) for arg in command]
        return subprocess.check_output(
            command + ["--"] + args,
            env={**os.environ, **(env or {})},
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
