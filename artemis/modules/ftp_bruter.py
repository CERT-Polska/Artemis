#!/usr/bin/env python3
import binascii
import ftplib
import io
import os
import ssl
from typing import List, Optional, Tuple

from karton.core import Task
from pydantic import BaseModel

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_host

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
    tls: bool = False
    is_writable: bool = False


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class FTPBruter(ArtemisBase):
    """
    Performs a brute force attack on FTP servers to guess login and password.
    """

    identity = "ftp_bruter"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.FTP.value},
    ]

    def run(self, current_task: Task) -> None:
        host = get_target_host(current_task)
        port = current_task.get_payload("port")

        result = FTPBruterResult()

        try:
            for username, password in BRUTE_CREDENTIALS:
                # We reconnect for each credential pair as some servers
                # (e.g. delfer/alpine-ftp-server:latest) don't work well
                # with multiple failed login attempts followed by a successful
                # one.

                # We want to check both FTP servers that require TLS and don't allow
                # cleartext connections and servers that don't support TLS.
                for tls in [False, True]:
                    if tls:
                        ssl_context = ssl.create_default_context()
                        ssl_context.check_hostname = False
                        ssl_context.verify_mode = ssl.VerifyMode.CERT_NONE
                        ftp = ftplib.FTP_TLS(context=ssl_context)
                    else:
                        ftp = ftplib.FTP()  # type: ignore

                    ftp.connect(host=host, port=port, timeout=10)

                    if tls:
                        try:
                            ftp.prot_p()
                        except ftplib.error_temp:
                            pass
                        except ftplib.error_perm:
                            pass

                    result.welcome = ftp.welcome
                    result.tls = tls

                    try:
                        self.throttle_request(lambda: ftp.login(username, password))

                        result.credentials.append((username, password))
                        result.files.extend(ftp.nlst())

                        data = io.BytesIO(b"")
                        ftp.storbinary(
                            f"STOR {Config.Modules.FTPBruter.FTP_BRUTER_TEST_FILE_NAME_PREFIX}-{binascii.hexlify(os.urandom(10)).decode('ascii')}.txt",
                            data,
                        )
                        result.is_writable = True
                    except ftplib.error_temp:
                        pass
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

        messages = []
        if result.credentials:
            messages.append(
                "Found working credentials for the FTP server: "
                + ", ".join(sorted([username + ":" + password for username, password in result.credentials]))
            )
        if result.is_writable:
            messages.append("The credentials allow creating files.")

        if messages:
            status = TaskStatus.INTERESTING
            status_reason = ", ".join(messages)
        else:
            status = TaskStatus.OK
            status_reason = None
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    FTPBruter().loop()
