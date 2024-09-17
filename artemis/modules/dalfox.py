#!/usr/bin/env python3
import json
import os
import random
import subprocess
import tempfile
import urllib
from typing import Any, Dict, List, Tuple
from urllib.parse import unquote

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.crawling import get_links_and_resources_on_same_domain
from artemis.module_base import ArtemisBase
from artemis.modules.data.static_extensions import STATIC_EXTENSIONS
from artemis.task_utils import get_target_url


class DalFox(ArtemisBase):
    """
    Running the Dalfox tool to scan for XSS vulnerabilities."""

    identity = "dalfox"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]
    dalfox_vulnerability_types = {"V": "Verify", "R": "Reflected", "G": "Grep"}

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)

    @staticmethod
    def _strip_query_string(url: str) -> str:
        url_parsed = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse(url_parsed._replace(query="", fragment=""))

    def prepare_output(self, vulnerabilities: List[Dict[str, Any]]) -> Tuple[List[str], List[Dict[str, Any]]]:
        message: List[Any] = []
        result: List[Any] = []

        for vulnerability in (vuln for vuln in vulnerabilities if vuln != {}):
            # Vulnerability - data concerning a single XSS vulnerability from the list found by the Dalfox module.
            # In the loop instruction, I remove duplicates and the empty result that Dalfox generates at the last
            # position of the results.
            flag = any(
                (
                    (vulnerability.get("param") in result_single_data.values())
                    and (vulnerability.get("type") in result_single_data.values())
                    and (vulnerability["data"].split("?")[0] == result_single_data["url"].split("?")[0])
                )
                for result_single_data in result
            )

            if not flag:
                data = {
                    "param": vulnerability.get("param"),
                    "evidence": unquote(vulnerability["evidence"]),
                    "type": vulnerability.get("type"),
                    "url": unquote(vulnerability["data"]),
                    "type_name": self.dalfox_vulnerability_types.get(vulnerability["type"]),
                }
                result.append(data)
                message.append(
                    f"On  {unquote(vulnerability['data'])} we identified an XSS vulnerability ("
                    f"type: {self.dalfox_vulnerability_types.get(vulnerability['type'])}) in "
                    f"the parameter: {vulnerability.get('param')}. "
                )

        result.sort(key=lambda x: x["param"])
        return message, result

    def scan(self, links_file_path: str, targets: List[str]) -> List[Dict[str, Any]]:
        vulnerabilities = []

        if Config.Miscellaneous.CUSTOM_USER_AGENT:
            additional_configuration = ["--user-agent", Config.Miscellaneous.CUSTOM_USER_AGENT]
        else:
            additional_configuration = []

        if Config.Limits.REQUESTS_PER_SECOND:
            milliseconds_per_request = int((1 / Config.Limits.REQUESTS_PER_SECOND) * 1000.0)
        else:
            milliseconds_per_request = 0

        try:
            command = [
                "dalfox",
                "--debug",
                "--delay",
                f"{milliseconds_per_request}",
                "file",
                links_file_path,
                "-X",
                "GET",
                "--format",
                "json",
            ] + additional_configuration
            self.log.info(f"Running command: {' '.join(command)}")

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
            )
            vulnerabilities = json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            self.log.error(f"Error when DalFox is running: {e}")

        return vulnerabilities

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(url)
        links = get_links_and_resources_on_same_domain(url)
        links = list(set(links) | set([self._strip_query_string(link) for link in links]))
        links = [
            link.split("#")[0]
            for link in links
            if not any(link.split("?")[0].lower().endswith(extension) for extension in STATIC_EXTENSIONS)
        ]

        random.shuffle(links)
        links = links[:50]
        links.append(url)

        _, path_to_file_with_links = tempfile.mkstemp()
        with open(path_to_file_with_links, "w") as file:
            file.write("\n".join(links))

        vulnerabilities = self.scan(links_file_path=path_to_file_with_links, targets=links)
        message, result = self.prepare_output(vulnerabilities)
        os.unlink(path_to_file_with_links)

        if message:
            status = TaskStatus.INTERESTING
            status_reason = str(message)
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data={"result": result})


if __name__ == "__main__":
    DalFox().loop()
