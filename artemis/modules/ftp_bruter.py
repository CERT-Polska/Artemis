#!/usr/bin/env python3
import ftplib
from typing import List, Optional, Tuple

from karton.core import Task
from pydantic import BaseModel

from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target
from artemis.utils import throttle_request

BRUTE_CREDENTIALS = [
    ("anonymous", ""),
    ("ftp", "ftp"),
    ("admin", "admin"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("root", "12345"),
    ("root", "root"),
    ("root", "toor"),
]


class FTPBruterResult(BaseModel):
    welcome: Optional[str] = None
    credentials: List[Tuple[str, str]] = []
    files: List[str] = []


class FTPBruter(ArtemisBase):
    """
    Performs a brute force attack on FTP servers to guess login and password
    """

    identity = "ftp_bruter"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.FTP.value},
    ]

    def run(self, current_task: Task) -> None:
        host = get_target(current_task)
        port = current_task.get_payload("port")

        result = FTPBruterResult()

        try:
            for username, password in BRUTE_CREDENTIALS:
                # We reconnect for each credential pair as some servers
                # (e.g. delfer/alpine-ftp-server:latest) don't work well
                # with multiple failed login attempts followed by a successful
                # one.
                ftp = ftplib.FTP()
                ftp.connect(host=host, port=port, timeout=10)
                result.welcome = ftp.welcome

                try:
                    throttle_request(lambda: ftp.login(username, password))
                    result.credentials.append((username, password))
                    result.files.extend(ftp.nlst())
                except ftplib.error_perm:
                    pass
                except EOFError:
                    pass
                finally:
                    ftp.close()
        except ConnectionRefusedError:
            pass
        except TimeoutError:
            pass

        if result.credentials:
            status = TaskStatus.INTERESTING
            status_reason = "Found working credentials for the FTP server: " + ", ".join(
                sorted([username + ":" + password for username, password in result.credentials])
            )
        else:
            status = TaskStatus.OK
            status_reason = None
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    FTPBruter().loop()
