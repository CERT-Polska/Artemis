"""
Landlock-based sandbox (landrun, https://github.com/zouuup/landrun)

TODO: restrict TCP egress on per-domain basis
TODO: Landlock can't restrict UDP egress on kernel <7.2, block it at iptables level
TODO: check if io_uring is a problem for this sandboxing.
"""

import ctypes
import os
import subprocess
import tempfile
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional

SANDBOX_CHECKS_SH = os.path.join(os.path.dirname(__file__), "sandboxing_payloads", "sandbox_checks.sh")
SANDBOX_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


class SandboxProfile(Enum):
    NOTCP_STRICT = auto()
    NOTCP_VCS = auto()
    NOTCP_PYTHON = auto()
    INTERNET = auto()

    def landrun_args(self, sandbox_rw_folder: Path) -> List[str]:
        command = ["landrun", "--ro", os.path.dirname(SANDBOX_CHECKS_SH), "--env", f"PATH={SANDBOX_PATH}"]
        if self is SandboxProfile.NOTCP_STRICT:
            args = command + ["--rox", "/bin/,/usr/bin/,/usr/lib,/lib"]
        elif self is SandboxProfile.NOTCP_VCS:
            args = command + [
                "--rox",
                "/usr/bin/git,/bin,/usr/bin,/usr/lib,/lib",
                "--ro",
                "/etc",
                "--rw",
                # {scratch_dir} is substituted for sandbox_rw_folder at the end of the function
                "/dev/null,{scratch_dir}",
                "--env",
                "SANDBOX_TMP={scratch_dir}",
            ]
        elif self is SandboxProfile.NOTCP_PYTHON:
            args = command + [
                "--rox",
                "/usr/local/bin/python3,/bin,/usr/bin,/usr/local/lib,/usr/lib,/lib",
                "--ro",
                "/opt",
                "--rw",
                "/dev/null,{scratch_dir}",
                "--env",
                "SANDBOX_TMP={scratch_dir}",
                # redirect the bytecode cache of the read-only /opt module code into the scratch dir
                "--env",
                "PYTHONPYCACHEPREFIX={scratch_dir}",
            ]
        elif self is SandboxProfile.INTERNET:
            args = command + [
                "--rox",
                "/usr,/bin,/sbin,/lib",
                "--ro",
                "/opt,/etc",
                "--rw",
                "/dev/null,{scratch_dir}",
                "--connect-tcp",
                "80,443",
                "--env",
                "SANDBOX_TMP={scratch_dir}",
            ]
        else:
            assert False

        # For paranoia, use .replace and not .format, so that the argument is not interpreted as a template
        # even though it is trusted.
        return [arg.replace("{scratch_dir}", str(sandbox_rw_folder)) for arg in args]

    def assertEnforced(self) -> None:
        # Deliberately not run_sandboxed - it verifies the confinement of the already-sandboxed current process.
        subprocess.check_output(["sh", SANDBOX_CHECKS_SH, self.name], stderr=subprocess.DEVNULL)


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
    additional_readonly_paths: Optional[List[str]] = None,
) -> bytes:
    """The sandboxed command reaches the writable scratch dir through the SANDBOX_TMP env set by the profile."""
    # TODO: ensure that calling .decode() is safe in Python.
    _assert_landlock_abi()
    with tempfile.TemporaryDirectory() as scratch_dir:
        command = profile.landrun_args(sandbox_rw_folder=Path(scratch_dir))
        for key, value in (env or {}).items():
            command += ["--env", f"{key}={value}"]
        for path in additional_readonly_paths or []:
            command += ["--ro", path]
        return subprocess.check_output(
            command + ["--"] + args,
            # Not sure where we want to pass env by --env, and where by actual env;
            # but it makes sense to strip the env that gets to landrun at all.
            env={"PATH": SANDBOX_PATH},
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
