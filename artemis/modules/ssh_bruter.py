#!/usr/bin/env python3
import socket
import time
from typing import List, Tuple

import paramiko
from karton.core import Task
from pydantic import BaseModel

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.ip_utils import is_ip_address
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_host

BRUTE_CREDENTIALS = [
    ("user", "password"),
    ("user", "user"),
    ("root", ""),
    ("root", "root"),
    ("root", "password"),
    ("root", "admin"),
    ("admin", "admin"),
    ("test", "test"),
    ("ppp", "ppp"),
]


class SSHBruterResult(BaseModel):
    credentials: List[Tuple[str, str]] = []


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class SSHBruter(ArtemisBase):
    """
    Performs a brute force attack on SSH.
    """

    identity = "ssh_bruter"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.SSH.value},
    ]

    def run(self, current_task: Task) -> None:
        host = get_target_host(current_task)

        if not is_ip_address(host):
            # Port scanner emits separate SERVICE tasks for all domains on a given IP address, and
            # (because it also scans IP addresses) also SERVICE tasks for all IP addresses.
            #
            # It makes no sense to scan all domains as they are processed by the ip_lookup karton
            # and we would scan the same IP multiple times. Therefore we scan only IPs.
            self.db.save_task_result(task=current_task, status=TaskStatus.OK)
            return

        port = current_task.get_payload("port")

        result = SSHBruterResult()
        for username, password in BRUTE_CREDENTIALS:
            try:
                client = paramiko.client.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.log.info(
                    "Attempting connect: hostname=%s, port=%s, username=%s, password=%s", host, port, username, password
                )
                # Some SSH servers drop connections after a large number of tries in a short
                # time period. This serves to combat this behavior.
                time.sleep(Config.Modules.SSHBruter.ADDITIONAL_BRUTE_FORCE_SLEEP_SECONDS)
                self.throttle_request(
                    lambda: client.connect(hostname=host, port=port, username=username, password=password)
                )
                result.credentials.append((username, password))
                client.close()
            except (
                paramiko.AuthenticationException,
                paramiko.BadHostKeyException,
                socket.error,
                socket.gaierror,
                paramiko.ssh_exception.NoValidConnectionsError,
                paramiko.ssh_exception.SSHException,
            ):
                pass

        if result.credentials:
            status = TaskStatus.INTERESTING
            status_reason = "Found working credentials for SSH connection: " + ", ".join(
                sorted([username + ":" + password for username, password in result.credentials])
            )
        else:
            status = TaskStatus.OK
            status_reason = None
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    SSHBruter().loop()
