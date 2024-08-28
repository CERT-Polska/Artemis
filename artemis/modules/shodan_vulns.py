#!/usr/bin/env python3
import os
from time import sleep
from typing import List

import shodan  # type: ignore
from karton.core import Task
from pydantic import BaseModel

from artemis import load_risk_class
from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.utils import build_logger


class ShodanVulnsResult(BaseModel):
    vulns: List[str] = []


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class ShodanVulns(ArtemisBase):
    """
    Lists vulnerabilities from Shodan.
    """

    identity = "shodan_vulns"
    filters = [{"type": TaskType.IP.value}]

    def scan(self, current_task: Task, ip: str) -> None:
        result = ShodanVulnsResult()
        found_vuln_descriptions = []
        shodan_client = shodan.Shodan(Config.Modules.Shodan.SHODAN_API_KEY)

        if vulns := shodan_client.host(ip).get("vulns"):
            result.vulns = vulns
            for vuln in vulns:
                found_vuln_descriptions.append(f"{vuln}")

        if len(found_vuln_descriptions) > 0:
            status = TaskStatus.INTERESTING
            status_reason = "Found vulnerabilities from Shodan API: " + ", ".join(sorted(found_vuln_descriptions))
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)

    def run(self, current_task: Task) -> None:
        ip = current_task.get_payload(TaskType.IP)
        with self.lock:
            sleep(1)
            self.scan(current_task, ip)


if __name__ == "__main__":
    if Config.Modules.Shodan.SHODAN_API_KEY:
        ShodanVulns().loop()
    else:
        no_api_key_message_printed_filename = "/.no-api-key-message-shown"

        if not os.path.exists(no_api_key_message_printed_filename):
            # We want to display the message only once
            LOGGER = build_logger(__name__)
            LOGGER.error("Shodan API key is required to start the Shodan vulnerability module.")
            LOGGER.error("Don't worry - all other modules can be used without this API key.")

            with open(no_api_key_message_printed_filename, "w"):
                pass
