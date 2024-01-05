#!/usr/bin/env python3
import json
import os
import subprocess
import urllib
from typing import Any, List

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url
from artemis.utils import check_output_log_on_error

EXPOSED_PANEL_TEMPLATE_PATH_PREFIX = "http/exposed-panels/"
CUSTOM_TEMPLATES_PATH = os.path.join(os.path.dirname(__file__), "data/nuclei_templates_custom/")


class Nuclei(ArtemisBase):
    """
    Runs Nuclei templates on URLs.
    """

    identity = "nuclei"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    batch_tasks = True
    task_max_batch_size = Config.Modules.Nuclei.NUCLEI_MAX_BATCH_SIZE

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
            self._exposed_panels_templates = [
                item
                for item in check_output_log_on_error(["nuclei", "-tl"], self.log).decode("ascii").split()
                if item.startswith(EXPOSED_PANEL_TEMPLATE_PATH_PREFIX)
            ]

            if Config.Modules.Nuclei.NUCLEI_CHECK_TEMPLATE_LIST:
                if len(self._critical_templates) == 0:
                    raise RuntimeError("Unable to obtain Nuclei critical-severity templates list")
                if len(self._high_templates) == 0:
                    raise RuntimeError("Unable to obtain Nuclei high-severity templates list")
                if len(self._exposed_panels_templates) == 0:
                    raise RuntimeError("Unable to obtain Nuclei exposed panels templates list")

            self._templates = [
                template
                for template in self._critical_templates + self._high_templates + self._exposed_panels_templates
                if template not in Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_SKIP
            ] + Config.Modules.Nuclei.NUCLEI_ADDITIONAL_TEMPLATES

            for custom_template_filename in os.listdir(CUSTOM_TEMPLATES_PATH):
                self._templates.append(os.path.join(CUSTOM_TEMPLATES_PATH, custom_template_filename))

    def run_multiple(self, tasks: List[Task]) -> None:
        self.log.info(f"running {len(self._templates)} templates on {len(tasks)} hosts.")

        if Config.Miscellaneous.CUSTOM_USER_AGENT:
            additional_configuration = ["-H", "User-Agent: " + Config.Miscellaneous.CUSTOM_USER_AGENT]
        else:
            additional_configuration = []

        command = [
            "nuclei",
            "-disable-update-check",
            "-etags",
            "intrusive",
            "-ni",
            "-templates",
            ",".join(self._templates),
            "-timeout",
            str(Config.Limits.REQUEST_TIMEOUT_SECONDS),
            "-jsonl",
            "-system-resolvers",
            "-bulk-size",
            str(len(tasks)),
            "-headless-bulk-size",
            str(len(tasks)),
            "-milliseconds-per-request",
            str(int((1 / Config.Limits.REQUESTS_PER_SECOND) * 1000.0 / len(tasks)))
            if Config.Limits.REQUESTS_PER_SECOND != 0
            else str(int(0)),
        ] + additional_configuration

        targets = []
        for task in tasks:
            targets.append(get_target_url(task))
            command.append("-target")
            command.append(get_target_url(task))

        data = check_output_log_on_error(
            command,
            self.log,
        )
        lines = data.decode("ascii", errors="ignore").split("\n")
        for line in lines:
            if line.strip():
                finding = json.loads(line)
                assert finding["host"] in targets, f'{finding["host"]} not found in {targets}'

        for task in tasks:
            result = []
            messages = []
            for line in lines:
                if line.strip():
                    finding = json.loads(line)
                    if finding["host"] != get_target_url(task):
                        continue

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
            self.db.save_task_result(task=task, status=status, status_reason=status_reason, data=result)

    def _is_homepage(self, url: str) -> bool:
        url_parsed = urllib.parse.urlparse(url)
        return url_parsed.path.strip("/") == "" and not url_parsed.query and not url_parsed.fragment


if __name__ == "__main__":
    Nuclei().loop()
