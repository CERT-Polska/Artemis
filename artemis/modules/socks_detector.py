#!/usr/bin/env python3
from karton.core import Task
from pydantic import BaseModel

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.socks_probe import probe_socks
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

        socks_version = probe_socks(host, port, timeout=Config.Limits.REQUEST_TIMEOUT_SECONDS)

        result = SocksDetectorResult(socks_version=socks_version or 0)

        if socks_version:
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.INTERESTING,
                status_reason=(f"SOCKS{socks_version} proxy on {host}:{port} allows unauthenticated connections."),
                data=result,
            )
        else:
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.OK,
                status_reason=None,
                data=result,
            )


if __name__ == "__main__":
    SocksDetector().loop()
