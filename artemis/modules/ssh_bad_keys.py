#!/usr/bin/env python3
import contextlib
import io
import socket
import subprocess
from typing import Any, Dict, List

import badkeys  # type: ignore[import-not-found]
import paramiko
from karton.core import Task
from pydantic import BaseModel

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.ip_utils import is_ip_address
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_host

SSH_KEY_TYPES_TO_CHECK = ["rsa", "dss", "ecdsa", "ed25519"]


class BadKeyFinding(BaseModel):
    key_type: str
    key_fingerprint: str
    check_name: str
    subtest: str
    lookup: str


class SSHBadKeysResult(BaseModel):
    bad_keys: List[BadKeyFinding] = []


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class SSHBadKeys(ArtemisBase):
    """
    Checks SSH host keys against known-bad key databases using the badkeys library.

    Detects compromised, hardcoded, or cryptographically weak SSH host keys such as
    those from the Debian OpenSSL PRNG bug (CVE-2008-0166), vendor firmware with
    hardcoded keys (rapid7/ssh-badkeys), and other known-vulnerable keys.
    """

    num_retries = Config.Miscellaneous.SLOW_MODULE_NUM_RETRIES
    identity = "ssh_bad_keys"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.SSH.value},
    ]

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)

        subprocess.call(["badkeys", "--update-bl"])

    def _get_host_keys(self, host: str, port: int) -> List[Dict[str, str]]:
        """Connect to SSH server and retrieve all host key types.

        Follows the same approach as badkeys.scanssh: iterates over key types,
        disabling all other types to force the server to present each one.
        """
        all_key_types = paramiko.Transport._preferred_keys  # type: ignore[attr-defined]
        keys = []

        for key_type in SSH_KEY_TYPES_TO_CHECK:
            transport = None
            try:
                disabled = [k for k in all_key_types if key_type not in k]
                transport = paramiko.Transport(
                    f"{host}:{port}",
                    disabled_algorithms={"keys": disabled},
                )
                # Suppress stderr output from paramiko during connection
                with contextlib.redirect_stderr(io.StringIO()):
                    transport.connect()
                key = transport.get_remote_server_key()

                keys.append(
                    {
                        "key_type": key.get_name(),
                        "ssh_pubkey_line": f"{key.get_name()} {key.get_base64()}",
                    }
                )
            except paramiko.ssh_exception.IncompatiblePeer:  # type: ignore[attr-defined]
                # Server doesn't support this key type, try next
                continue
            except (
                paramiko.ssh_exception.SSHException,
                socket.error,
                socket.gaierror,
                EOFError,
                ConnectionResetError,
            ):
                # Can't connect at all, don't try more key types
                break
            finally:
                if transport:
                    transport.close()

        return keys

    def run(self, current_task: Task) -> None:
        host = get_target_host(current_task)

        if not is_ip_address(host):
            # Same reasoning as ssh_bruter: port scanner emits separate SERVICE tasks
            # for all domains on a given IP, so we only scan IPs to avoid duplicates.
            self.db.save_task_result(task=current_task, status=TaskStatus.OK)
            return

        port = current_task.get_payload("port")

        self.log.info("Checking SSH host keys on %s:%s", host, port)
        keys = self._get_host_keys(host, port)
        self.log.info("Retrieved %d host key(s) from %s:%s", len(keys), host, port)

        result = SSHBadKeysResult()
        for key_info in keys:
            check_result = badkeys.checksshpubkey(key_info["ssh_pubkey_line"])

            if check_result.get("results"):
                for check_name, details in check_result["results"].items():
                    if isinstance(details, dict) and details.get("detected"):
                        result.bad_keys.append(
                            BadKeyFinding(
                                key_type=key_info["key_type"],
                                key_fingerprint=check_result.get("spkisha256", "unknown"),
                                check_name=check_name,
                                subtest=details.get("subtest", "unknown"),
                                lookup=details.get("lookup", ""),
                            )
                        )

        if result.bad_keys:
            status = TaskStatus.INTERESTING
            descriptions = [f"{bk.key_type} ({bk.subtest})" for bk in result.bad_keys]
            status_reason = "Found known-bad SSH host key(s): " + ", ".join(descriptions)
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    SSHBadKeys().loop()
