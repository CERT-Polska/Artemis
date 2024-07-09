import re
from typing import Any, Dict, List, Union

from karton.core import Task

from artemis import http_requests
from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.fallback_api_cache import FallbackAPICache
from artemis.modules.base.base_newer_version_comparer import (
    BaseNewerVersionComparerModule,
)


class JoomlaScanner(BaseNewerVersionComparerModule):
    """
    Joomla scanner - checks whether the version is old or registration is enabled.
    """

    identity = "joomla_scanner"
    filters = [
        {"type": TaskType.WEBAPP.value, "webapp": WebApplication.JOOMLA.value},
    ]
    software_name = "joomla"

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
            gh_api_response = FallbackAPICache.Urls.JOOMLA_LATEST_RELEASE.value.get()

            if gh_api_response.json()["tag_name"] != joomla_version and self.is_version_obsolete(joomla_version):
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
    JoomlaScanner().loop()  # type: ignore
