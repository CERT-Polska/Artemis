#!/usr/bin/env python3
import json
import subprocess
import urllib
from typing import Any, Dict, List

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.crawling import get_links_and_resources_on_same_domain
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url


class DalFox(ArtemisBase):
    """
    Runs Dalfox .
    """

    identity = "dalfox"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)

    @staticmethod
    def _strip_query_string(url: str) -> str:
        url_parsed = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse(url_parsed._replace(query="", fragment=""))

    @staticmethod
    def delete_message_str(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        for vulnerability in vulnerabilities:
            del vulnerability["message_id"]

        return vulnerabilities

    @staticmethod
    def scan(links_file_path: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        try:
            result = subprocess.run(
                ["dalfox", "file", links_file_path, "-X", "GET", "--format", "json"], capture_output=True, text=True
            )
            vulnerabilities = json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"Error when DalFox is running: {e}")

        return vulnerabilities

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        links = get_links_and_resources_on_same_domain(url)
        links.append(url)
        links = list(set(links) | set([self._strip_query_string(link) for link in links]))

        links_file_path = "artemis/modules/data/dalfox/links.txt"
        with open(links_file_path, "w") as file:
            for link in links:
                file.write(link + "\n")

        message = self.scan(links_file_path=links_file_path)

        if message:
            status = TaskStatus.INTERESTING
            status_reason = str(message)
        else:
            status = TaskStatus.OK
            status_reason = None

        result = []
        for vulnerability in message:
            data = {
                "type": vulnerability.get("type"),
                "method": vulnerability.get("method"),
                "parameter": vulnerability.get("parameter"),
                "payload": vulnerability.get("payload"),
                "url": vulnerability.get("url"),
            }
            result.append(data)

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data={"result": result})


if __name__ == "__main__":
    DalFox().loop()
