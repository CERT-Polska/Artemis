import re
from typing import Any, Dict, List, Union

import requests
from karton.core import Task

from artemis.binds import Application, TaskStatus
from artemis.module_base import ArtemisBase

WP_MIN_SUPPORTED = 60


class WordPressScanner(ArtemisBase):
    """
    WordPress scanner
    """

    identity = "wp_scanner"
    filters = [
        {"webapp": Application.WORDPRESS},
    ]

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
            major, minor, _ = wp_version.split(".")
            if int(major + minor) < WP_MIN_SUPPORTED:
                found_problems.append(f"version is too old: {major}.{minor}")
            else:
                # Returns all possible updates from current version
                wp_api_response = requests.get(
                    f"https://api.wordpress.org/core/version-check/1.7/?version={wp_version}", timeout=5
                )
                released_versions = [offer["version"] for offer in wp_api_response.json()["offers"]]
                major_minor = f"{major}.{minor}"
                for released_version in released_versions:
                    if released_version.startswith(major_minor):
                        found_problems.append("update is available")

            # Enumerate installed plugins
            result["wp_plugins"] = re.findall("wp-content/plugins/([^/]+)/.+ver=([0-9.]+)", response.text)

        if found_problems:
            status = TaskStatus.INTERESTING
            status_reason = "Found WordPress problems: " + ", ".join(sorted(found_problems))
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)

    def run(self, current_task: Task) -> None:
        url = current_task.get_payload("url")
        self.scan(current_task, url)


if __name__ == "__main__":
    WordPressScanner().loop()
