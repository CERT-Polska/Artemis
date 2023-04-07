import json
import re
from datetime import datetime
from typing import Any, Dict, List, Union

import pytz
import requests
import semver
from karton.core import Task

from artemis import http_requests
from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.config import Config
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
    def is_version_old(self, version: str, age_threshold_days: int = Config.JOOMLA_VERSION_AGE_DAYS) -> bool:
        data = json.loads(self.cached_get("https://api.github.com/repos/joomla/joomla-cms/releases", "versions"))

        version_parsed = semver.VersionInfo.parse(version)
        if version_parsed.major < 3:
            return True

        is_current_version_old = True  # If we don't find the version on releases list, that means, it's old
        for release in data:
            if release["tag_name"] == version:
                version_age = datetime.utcnow().replace(tzinfo=pytz.utc) - datetime.fromisoformat(
                    release["published_at"]
                )
                is_current_version_old = version_age.days > age_threshold_days

        is_newer_version_available = False
        for release in data:
            release_version_parsed = semver.VersionInfo.parse(release["tag_name"])
            have_same_major_version = release_version_parsed.major == version_parsed.major

            # Semver compare returns 1 if the latter version is greater, 0 if they are equal, and -1 if
            # the latter version is smaller.
            is_release_newer = release_version_parsed.compare(version_parsed) > 0
            if have_same_major_version and is_release_newer:
                is_newer_version_available = True

        # To consider a version old, it must:
        # - be obsolete enough (we don't want to send notifications if a version was released yesterday)
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
