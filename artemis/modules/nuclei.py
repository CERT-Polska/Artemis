#!/usr/bin/env python3
import json
import random
import string
import subprocess
import urllib
from typing import Any

from karton.core import Task

from artemis import http_requests
from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.utils import check_output_log_on_error

TEMPLATES_THAT_MATCH_ON_PHPINFO = {
    "http/cnvd/2020/CNVD-2020-23735.yaml",
    "http/cves/2015/CVE-2015-4050.yaml",
    "http/cves/2019/CVE-2019-9041.yaml",
    "http/cves/2020/CVE-2020-5776.yaml",
    "http/cves/2020/CVE-2020-5847.yaml",
    "http/cves/2021/CVE-2021-40870.yaml",
    "http/cves/2022/CVE-2022-0885.yaml",
    "http/cves/2022/CVE-2022-1020.yaml",
    "http/vulnerabilities/other/ecshop-sqli.yaml",
    "http/vulnerabilities/thinkcmf/thinkcmf-rce.yaml",
}


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
            self._exposed_panels_templates = [
                item
                for item in check_output_log_on_error(["nuclei", "-tl"], self.log).decode("ascii").split()
                if item.startswith("http/exposed_panels/")
            ]

            if Config.NUCLEI_CHECK_TEMPLATE_LIST:
                if len(self._critical_templates) == 0:
                    raise RuntimeError("Unable to obtain Nuclei critical-severity templates list")
                if len(self._high_templates) == 0:
                    raise RuntimeError("Unable to obtain Nuclei high-severity templates list")
                if len(self._exposed_panels_templates) == 0:
                    raise RuntimeError("Unable to obtain Nuclei exposed panels templates list")

            self._templates = [
                template
                for template in self._critical_templates + self._high_templates + self._exposed_panels_templates
                if template not in Config.NUCLEI_TEMPLATES_TO_SKIP
            ] + Config.NUCLEI_ADDITIONAL_TEMPLATES

    def run(self, current_task: Task) -> None:
        target = current_task.payload["url"]
        content = current_task.payload["content"]

        templates = []
        # We want to run PhpMyAdmin Nuclei templates only when we identified that a given URL runs
        # PhpMyAdmin.
        if "<title>phpMyAdmin</title>" in content:
            templates.append("http/default-logins/phpmyadmin/phpmyadmin-default-login.yaml")

        self.log.info(f"path is {urllib.parse.urlparse(target).path}")
        if self._is_homepage(target):
            self.log.info(f"adding {len(self._templates)} templates")
            templates.extend(self._templates)

        self.log.info(f"nuclei: running {len(templates)} templates on {target}")

        if len(templates) == 0:
            self.db.save_task_result(task=current_task, status=TaskStatus.OK, status_reason=None, data={})
            return

        random_token = "".join(random.choices(string.ascii_letters + string.digits, k=16))
        dummy_url = target.rstrip("/") + "/" + random_token
        try:
            dummy_content = http_requests.get(dummy_url).content
        except Exception:
            dummy_content = ""
        has_phpinfo_on_random_url = "phpinfo()" in dummy_content

        # Some templates check whether a vulnerability is present by trying to call phpinfo() and checking
        # whether it succeeded. Some websites return phpinfo() on all URLs. This is to prevent Artemis
        # return false positives for these websites.
        if has_phpinfo_on_random_url:
            templates = sorted(list(set(templates) - TEMPLATES_THAT_MATCH_ON_PHPINFO))

        if Config.CUSTOM_USER_AGENT:
            additional_configuration = ["-H", "User-Agent: " + Config.CUSTOM_USER_AGENT]
        else:
            additional_configuration = []

        command = [
            "nuclei",
            "-disable-update-check",
            "-etags",
            "intrusive",
            "-ni",
            "-target",
            target,
            "-templates",
            ",".join(templates),
            "-timeout",
            str(Config.REQUEST_TIMEOUT_SECONDS),
            "-jsonl",
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

    def _is_homepage(self, url: str) -> bool:
        url_parsed = urllib.parse.urlparse(url)
        return url_parsed.path.strip("/") == "" and not url_parsed.query and not url_parsed.fragment


if __name__ == "__main__":
    Nuclei().loop()
