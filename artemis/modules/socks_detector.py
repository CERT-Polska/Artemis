#!/usr/bin/env python3
import socket

from karton.core import Task
from pydantic import BaseModel

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_host


class SocksDetectorResult(BaseModel):
    socks_version: int = 0


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class SocksDetector(ArtemisBase):

    identity = "socks_detector"

    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.SOCKS.value},
    ]

    def run(self, current_task: Task) -> None:
        host = get_target_host(current_task)
        port = current_task.get_payload("port")

        result = SocksDetectorResult()

        # SOCKS5
        try:
            with socket.create_connection(
                (host, port),
                timeout=Config.Limits.REQUEST_TIMEOUT_SECONDS,
            ) as sock:

                sock.sendall(b"\x05\x01\x00")
                response = sock.recv(2)

                if len(response) == 2 and response == b"\x05\x00":
                    result.socks_version = 5

                    self.db.save_task_result(
                        task=current_task,
                        status=TaskStatus.INTERESTING,
                        status_reason=f"SOCKS5 proxy on {host}:{port} allows unauthenticated connections.",
                        data=result,
                    )
                    return
        except Exception:
            pass

        # SOCKS4
        try:
            with socket.create_connection(
                (host, port),
                timeout=Config.Limits.REQUEST_TIMEOUT_SECONDS,
            ) as sock:

                sock.sendall(b"\x04\x01\x00\x50\x7f\x00\x00\x01\x00")
                response = sock.recv(8)

                if len(response) >= 2 and response[1] == 0x5A:
                    result.socks_version = 4

                    self.db.save_task_result(
                        task=current_task,
                        status=TaskStatus.INTERESTING,
                        status_reason=f"SOCKS4 proxy on {host}:{port} allows unauthenticated connections.",
                        data=result,
                    )
                    return
        except Exception:
            pass

        self.db.save_task_result(
            task=current_task,
            status=TaskStatus.OK,
            status_reason=None,
            data=result,
        )


if __name__ == "__main__":
    SocksDetector().loop()
