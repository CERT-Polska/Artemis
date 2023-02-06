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
        {"type": TaskType.URL.value},
    ]

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        subprocess.call(["nuclei", "-update-templates"])
        self._critical_templates = subprocess.check_output(["nuclei", "-s", "critical", "-tl"]).decode("ascii").split()

    def run(self, current_task: Task) -> None:
        target = current_task.payload["url"]
        content = current_task.payload["content"]

        templates = []
        # We want to run PhpMyAdmin Nuclei templates only when we identified that a given URL runs
        # PhpMyAdmin.
        if "<title>phpMyAdmin</title>" in content:
            templates.append("default-logins/phpmyadmin/phpmyadmin-default-login.yaml")

        if urllib.parse.urlparse(target).path.strip("/") == "":
            templates.extend(self._critical_templates)

        self.log.info(f"nuclei: running {len(templates)} templates on {target}")

        if len(templates) == 0:
            self.db.save_task_result(task=current_task, status=TaskStatus.OK, status_reason=None, data={})
            return

        if Config.CUSTOM_USER_AGENT:
            additional_configuration = ["-H", "User-Agent: " + Config.CUSTOM_USER_AGENT]
        else:
            additional_configuration = []

        host = urllib.parse.urlparse(target).hostname
        with lock_requests_for_ip(get_ip_for_locking(host)):
            command = [
                "nuclei",
                "-disable-update-check",
                "-ni",
                "-target",
                target,
                "-templates",
                ",".join(templates),
                "-json",
                "-resolvers",
                "/dev/null",
                "-system-resolvers",
                "-spr",
                str(Config.SECONDS_PER_REQUEST_FOR_ONE_IP),
            ] + additional_configuration

            data = subprocess.check_output(
                command,
                stderr=subprocess.DEVNULL,
            )

        result = []
        messages = []
        for line in data.decode("ascii", errors="ignore").split("\n"):
            if line.strip():
                finding = json.loads(line)
                result.append(finding)
                messages.append(
                    f"[{finding['info']['severity']}] {finding['info'].get('name')} {finding['info'].get('description')}"
                )

        if messages:
            status = TaskStatus.INTERESTING
            status_reason = ", ".join(messages)
        else:
            status = TaskStatus.OK
            status_reason = None
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    Nuclei().loop()
