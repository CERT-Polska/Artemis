#!/usr/bin/env python3
import json
import subprocess
import urllib
from typing import Any

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.utils import check_output_log_on_error


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
        with self.lock:
            subprocess.call(["nuclei", "-update-templates"])
            self._critical_templates = (
                check_output_log_on_error(["nuclei", "-s", "critical", "-tl"], self.log).decode("ascii").split()
            )
            self._high_templates = (
                check_output_log_on_error(["nuclei", "-s", "high", "-tl"], self.log).decode("ascii").split()
            )

            if Config.NUCLEI_CHECK_TEMPLATE_LIST:
                if len(self._critical_templates) == 0:
                    raise RuntimeError("Unable to obtain Nuclei critical-severity templates list")
                if len(self._high_templates) == 0:
                    raise RuntimeError("Unable to obtain Nuclei high-severity templates list")

            # Skipping these two templates as they caused panic: runtime error: integer divide by zero in
            # github.com/projectdiscovery/retryabledns
            self._templates = [
                template
                for template in self._critical_templates + self._high_templates
                if template != "dns/azure-takeover-detection.yaml" and template != "dns/elasticbeantalk-takeover.yaml"
            ]

    def run(self, current_task: Task) -> None:
        target = current_task.payload["url"]
        content = current_task.payload["content"]

        templates = []
        # We want to run PhpMyAdmin Nuclei templates only when we identified that a given URL runs
        # PhpMyAdmin.
        if "<title>phpMyAdmin</title>" in content:
            templates.append("default-logins/phpmyadmin/phpmyadmin-default-login.yaml")

        self.log.info(f"path is {urllib.parse.urlparse(target).path}")
        if urllib.parse.urlparse(target).path.strip("/") == "":
            self.log.info(f"adding {len(self._templates)} templates")
            templates.extend(self._templates)

        self.log.info(f"nuclei: running {len(templates)} templates on {target}")

        if len(templates) == 0:
            self.db.save_task_result(task=current_task, status=TaskStatus.OK, status_reason=None, data={})
            return

        if Config.CUSTOM_USER_AGENT:
            additional_configuration = ["-H", "User-Agent: " + Config.CUSTOM_USER_AGENT]
        else:
            additional_configuration = []

        command = [
            "nuclei",
            "-disable-update-check",
            "-ni",
            "-target",
            target,
            "-templates",
            ",".join(templates),
            "-timeout",
            str(Config.REQUEST_TIMEOUT_SECONDS),
            "-json",
            "-resolvers",
            "/dev/null",
            "-system-resolvers",
            "-spr",
            str(Config.SECONDS_PER_REQUEST_FOR_ONE_IP),
        ] + additional_configuration

        data = check_output_log_on_error(
            command,
            self.log,
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
