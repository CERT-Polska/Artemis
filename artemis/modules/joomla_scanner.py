import datetime
import json
import re
from typing import Any, Dict, List, Union

import pytz
import requests
import semver
from karton.core import Task

from artemis import http_requests
from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.module_base import ArtemisBase


class JoomlaScanner(ArtemisBase):
    """
    Joomla scanner - checks whether the version is old or registration is enabled.
    """

    identity = "joomla_scanner"
    filters = [
        {"type": TaskType.WEBAPP.value, "webapp": WebApplication.JOOMLA.value},
    ]

    # This is a heuristic so that we can avoid parsing CVE list
    def is_version_old(self, version: str, age_threshold_days: int = 30) -> bool:
        cache_key = "versions"
        if not self.cache.get(cache_key):
            data = requests.get("https://api.github.com/repos/joomla/joomla-cms/releases").json()
            data_as_json = json.dumps(data)
            self.cache.set(cache_key, data_as_json.encode("utf-8"))
        else:
            cache_result = self.cache.get(cache_key)
            assert cache_result
            data = json.loads(cache_result)

        version_parsed = semver.VersionInfo.parse(version)
        if version_parsed.major < 3:
            return True

        is_current_version_old = True  # If we don't find the version on releases list, that means, it's old
        for release in data:
            if release["tag_name"] == version:
                is_current_version_old = (
                    datetime.datetime.utcnow().replace(tzinfo=pytz.utc)
                    - datetime.datetime.fromisoformat(release["published_at"])
                ).days > age_threshold_days

        is_newer_version_available = False
        for release in data:
            release_version = release["tag_name"]
            release_version_parsed = semver.VersionInfo.parse(release_version)
            if (
                release_version_parsed.major == version_parsed.major
                and release_version_parsed.compare(version_parsed) > 0
            ):
                is_newer_version_available = True

        # To consider a version old, it must:
        # - be obsolete enough (we don't want to send notifications if a version has been released yesterday)
        # - a newer version for a given branch (Joomla 3.x or Joomla 4.x) should be available (so that we don't consider
        #   3.10.11 to be old because it's the newest version for the 3.x branch).
        return is_current_version_old and is_newer_version_available

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
            if gh_api_response.json()["tag_name"] != joomla_version and self.is_version_old(joomla_version):
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
