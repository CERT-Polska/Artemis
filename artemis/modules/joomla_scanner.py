import datetime
import json
import re
from typing import Any, Dict, List, Union

import pytz
import requests
from karton.core import Task

from artemis import http_requests
from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.module_base import ArtemisBase


class JoomlaScanner(ArtemisBase):
    """
    Joomla scanner
    """

    identity = "joomla_scanner"
    filters = [
        {"type": TaskType.WEBAPP, "webapp": WebApplication.JOOMLA},
    ]

    # This is a heuristic so that we can avoid parsing CVE list
    def _is_version_old(self, version: str, age_threshold_days: int = 365) -> bool:
        cache_key = "versions"
        if not self.cache.get(cache_key):
            data = requests.get("https://api.github.com/repos/joomla/joomla-cms/releases").json()
            data_as_json = json.dumps(data)
            self.cache.set(cache_key, data_as_json.encode("utf-8"))
        else:
            cache_result = self.cache.get(cache_key)
            assert cache_result
            data = json.loads(cache_result)

        for release in data:
            if release["tag_name"] == version:
                return (
                    datetime.datetime.utcnow().replace(tzinfo=pytz.utc)
                    - datetime.datetime.fromisoformat(release["published_at"])
                ).days > age_threshold_days

        # Cannot check version age
        return True

    def run(self, current_task: Task) -> None:
        url = current_task.get_payload("url")
        found_problems = []
        result: Dict[str, Union[str, bool, List[Any]]] = {}

        # Check for open registration
        registration_url = f"{url}/index.php?option=com_users&view=registration"
        response = http_requests.get(registration_url)
        if "registration.register" in response.text:
            found_problems.append(f"Joomla registration is enabled in {registration_url}")
            result["registration_url"] = registration_url

        # Check if they are running latest patch version
        response = http_requests.get(f"{url}/administrator/manifests/files/joomla.xml")
        if match := re.search("<version>([0-9]+\\.[0-9]+\\.[0-9]+)</version>", response.text):
            joomla_version = match.group(1)
            result["joomla_version"] = joomla_version
            # Get latest release in repo from GitHub API
            gh_api_response = requests.get("https://api.github.com/repos/joomla/joomla-cms/releases/latest")
            if gh_api_response.json()["tag_name"] != joomla_version and self._is_version_old(joomla_version):
                found_problems.append(f"Joomla version is too old: {joomla_version}")
                result["joomla_version_is_too_old"] = True

        if found_problems:
            status = TaskStatus.INTERESTING
            status_reason = "Found problems: " + ", ".join(sorted(found_problems))
        else:
            status = TaskStatus.OK
            status_reason = None
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    JoomlaScanner().loop()
