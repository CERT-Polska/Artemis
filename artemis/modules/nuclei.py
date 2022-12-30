#!/usr/bin/env python3
import json
import subprocess
import urllib
from typing import Any

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.request_limit import get_ip_for_locking, lock_requests_for_ip


class Nuclei(ArtemisBase):
    """
    Runs Nuclei templates on URLs.
    """

    identity = "nuclei"
    filters = [
        {"type": TaskType.URL},
    ]

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        subprocess.call(["nuclei", "-update-templates"])

    def run(self, current_task: Task) -> None:
        target = current_task.payload["url"]
        content = current_task.payload["content"]

        templates = ["exposures/tokens/"]
        # We want to run PhpMyAdmin Nuclei templates only when we identified that a given URL runs
        # PhpMyAdmin.
        if 'name="imLogo" alt="phpMyAdmin"' in content:
            templates.append("default-logins/phpmyadmin/phpmyadmin-default-login.yaml")

        if Config.CUSTOM_USER_AGENT:
            additional_configuration = ["-H", "User-Agent: " + Config.CUSTOM_USER_AGENT]
        else:
            additional_configuration = []

        host = urllib.parse.urlparse(target).hostname
        with lock_requests_for_ip(get_ip_for_locking(host)):
            data = subprocess.check_output(
                [
                    "nuclei",
                    "-target",
                    target,
                    "-templates",
                    ",".join(templates),
                    "-json",
                    "-spr",
                    str(Config.SECONDS_PER_REQUEST_FOR_ONE_IP),
                ]
                + additional_configuration,
                stderr=subprocess.DEVNULL,
            )

        result = []
        messages = []
        for line in data.decode("ascii", errors="ignore").split("\n"):
            if line.strip():
                finding = json.loads(line)
                result.append(finding)
                messages.append(f"[{finding['info']['severity']}] {finding['info']['description']}")

        if messages:
            status = TaskStatus.INTERESTING
            status_reason = ", ".join(messages)
        else:
            status = TaskStatus.OK
            status_reason = None
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    Nuclei().loop()
