import json
import re
from typing import Any, Dict, List, Union

import requests
from karton.core import Task

from artemis.binds import Application, TaskStatus
from artemis.module_base import ArtemisBase


class WordPressScanner(ArtemisBase):
    """
    WordPress scanner
    """

    identity = "wp_scanner"
    filters = [
        {"webapp": Application.WORDPRESS},
    ]

    def _is_version_insecure(self, version: str) -> bool:
        cache_key = "version-stability"
        if not self.cache.get(cache_key):
            data = requests.get("https://api.wordpress.org/core/stable-check/1.0/").json()
            data_as_json = json.dumps(data)
            self.cache.set(cache_key, data_as_json)
        else:
            data = json.load(self.cache.get(cache_key))

        if version not in data:
            raise Exception(f"Cannot check version stability: {version}")

        assert data[version] in ["insecure", "outdated", "latest"]
        return data[version]

    def scan(self, current_task: Task, url: str) -> None:
        found_problems = []
        result: Dict[str, Union[str, List[Any]]] = {}

        # Check for open registration
        registration_url = f"{url}/wp-login.php?action=register"
        response = requests.get(registration_url, verify=False, timeout=5)
        if '<form name="registerform" id="registerform"' in response.text:
            found_problems.append(f"registration is open on {registration_url}")
            result["registration_url"] = registration_url

        # Check if they are running latest patch version
        response = requests.get(url, verify=False, timeout=5)
        wp_version = None
        if match := re.search('<meta name="generator" content="WordPress ([0-9]+\\.[0-9]+\\.[0-9]+)', response.text):
            wp_version = match.group(1)
        elif match := re.search("wp-includes/js/wp-embed.min.js\\?ver=([0-9]+\\.[0-9]+\\.[0-9]+)", response.text):
            wp_version = match.group(1)

        if wp_version:
            result["wp_version"] = wp_version
            if self._is_version_insecure(wp_version):
                found_problems.append(f"WordPress {wp_version} is considered insecure")

            # Enumerate installed plugins
            result["wp_plugins"] = re.findall("wp-content/plugins/([^/]+)/.+ver=([0-9.]+)", response.text)

        if found_problems:
            status = TaskStatus.INTERESTING
            status_reason = "Found WordPress problems: " + ", ".join(found_problems)
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)

    def run(self, current_task: Task) -> None:
        url = current_task.get_payload("url")
        self.scan(current_task, url)


if __name__ == "__main__":
    WordPressScanner().loop()
