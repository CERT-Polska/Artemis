#!/usr/bin/env python3
import json
import subprocess

from karton.core import Task

from artemis import load_risk_class
from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.config import Config
from artemis.module_base import ArtemisBase


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class JoomlaExtensions(ArtemisBase):
    """
    Checks whether Joomla! extensions are up-to-date.
    """

    identity = "joomla_extensions"
    filters = [
        {"type": TaskType.WEBAPP.value, "webapp": WebApplication.JOOMLA.value},
    ]

    def run(self, current_task: Task) -> None:
        url = current_task.get_payload("url")

        command = [
            "python",
            "/joomla-scanner/myscanner.py",
            "-u",
            url,
        ]

        if Config.Miscellaneous.CUSTOM_USER_AGENT:
            command.extend(["--user-agent", Config.Miscellaneous.CUSTOM_USER_AGENT])
        if self.requests_per_second_for_current_tasks:
            command.extend(["--rate-limit", str(int(self.requests_per_second_for_current_tasks))])

        result = subprocess.check_output(command, cwd="/joomla-scanner").decode("utf-8", errors="ignore")

        self.log.info("joomla-scanner output: %s", result)
        messages = []
        outdated_extensions = []

        for line in result.split("\n"):
            if line.startswith("{"):
                data = json.loads(line.replace("'", '"'))
                for value in data.values():
                    messages.append(
                        f"Found outdated Joomla! extension: {value['matched_extension_name']} version "
                        f"should be {value['matched_extension_version']} and is {value['identified_version']}"
                    )
                    outdated_extensions.append(
                        {
                            "name": value["matched_extension_name"],
                            "upstream_version": value["matched_extension_version"],
                            "version_on_website": value["identified_version"],
                            "urls": value["urls"],
                        }
                    )

        if messages:
            status = TaskStatus.INTERESTING
            status_reason = ", ".join(messages)
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={
                "outdated_extensions": outdated_extensions,
            },
        )


if __name__ == "__main__":
    JoomlaExtensions().loop()
