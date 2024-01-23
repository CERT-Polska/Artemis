#!/usr/bin/env python3
import json
import os
import random
import subprocess
import urllib
from typing import Any, Dict, List

from bs4 import BeautifulSoup
from karton.core import Task

from artemis import http_requests
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

        # We clone this repo in __init__ (on karton start) so that it will get periodically
        # re-cloned when the container gets retarted every 𝑛 tasks. The same logic lies behind
        # updating the Nuclei templates in __init__.
        subprocess.call(["git", "clone", "https://github.com/Ostorlab/KEV/", "/known-exploited-vulnerabilities/"])
        with self.lock:
            subprocess.call(["nuclei", "-update-templates"])
            self._known_exploited_vulnerability_templates = (
                check_output_log_on_error(["find", "/known-exploited-vulnerabilities/nuclei/"], self.log)
                .decode("ascii")
                .split()
            )
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
                if len(self._known_exploited_vulnerability_templates) == 0:
                    raise RuntimeError(
                        "Unable to obtain Nuclei known exploited vulnerability templates list from https://github.com/Ostorlab/KEV/"
                    )
                if len(self._critical_templates) == 0:
                    raise RuntimeError("Unable to obtain Nuclei critical-severity templates list")
                if len(self._high_templates) == 0:
                    raise RuntimeError("Unable to obtain Nuclei high-severity templates list")
                if len(self._exposed_panels_templates) == 0:
                    raise RuntimeError("Unable to obtain Nuclei exposed panels templates list")

            self._templates = [
                template
                for template in self._critical_templates
                + self._high_templates
                + self._exposed_panels_templates
                + self._known_exploited_vulnerability_templates
                if template not in Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_SKIP
            ] + Config.Modules.Nuclei.NUCLEI_ADDITIONAL_TEMPLATES

            for custom_template_filename in os.listdir(CUSTOM_TEMPLATES_PATH):
                self._templates.append(os.path.join(CUSTOM_TEMPLATES_PATH, custom_template_filename))

    def _get_links(self, url: str) -> List[str]:
        url_parsed = urllib.parse.urlparse(url)
        response = http_requests.get(url)
        soup = BeautifulSoup(response.text)
        links = []
        for tag in soup.find_all():
            new_url = None
            for attribute in ["src", "href"]:
                if attribute not in tag.attrs:
                    continue

                new_url = urllib.parse.urljoin(url, tag[attribute])
                new_url_parsed = urllib.parse.urlparse(new_url)

                if url_parsed.netloc == new_url_parsed.netloc:
                    links.append(new_url)
        random.shuffle(links)

        links = links[: Config.Modules.Nuclei.NUCLEI_MAX_NUM_LINKS_TO_PROCESS]
        return links

    def _scan(self, templates: List[str], targets: List[str]) -> List[Dict[str, Any]]:
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
            str(len(targets)),
            "-headless-bulk-size",
            str(len(targets)),
            "-milliseconds-per-request",
            str(int((1 / Config.Limits.REQUESTS_PER_SECOND) * 1000.0 / len(targets)))
            if Config.Limits.REQUESTS_PER_SECOND != 0
            else str(int(0)),
        ] + additional_configuration

        for target in targets:
            command.append("-target")
            command.append(target)

        data = check_output_log_on_error(
            command,
            self.log,
        )
        lines = data.decode("ascii", errors="ignore").split("\n")

        findings = []
        for line in lines:
            if line.strip():
                finding = json.loads(line)
                assert finding["host"] in targets, f'{finding["host"]} not found in {targets}'
                findings.append(finding)
        return findings

    def run_multiple(self, tasks: List[Task]) -> None:
        self.log.info(f"running {len(self._templates)} templates on {len(tasks)} hosts.")

        targets = []
        for task in tasks:
            targets.append(get_target_url(task))

        links_per_task = {}
        links = []
        for task in tasks:
            links_per_task[task.uid] = self._get_links(get_target_url(task))
            links.extend(links_per_task[task.uid])

        findings = self._scan(self._templates, targets) + self._scan(
            Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_RUN_ON_HOMEPAGE_LINKS, links
        )

        for task in tasks:
            result = []
            messages = []
            for finding in findings:
                if finding["host"] not in [get_target_url(task)] + links_per_task[task.uid]:
                    continue

                result.append(finding)
                messages.append(
                    f"[{finding['info']['severity']}] {finding['host']}: {finding['info'].get('name')} {finding['info'].get('description')}"
                )

            if messages:
                status = TaskStatus.INTERESTING
                status_reason = ", ".join(messages)
            else:
                status = TaskStatus.OK
                status_reason = None
            self.db.save_task_result(task=task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    Nuclei().loop()
