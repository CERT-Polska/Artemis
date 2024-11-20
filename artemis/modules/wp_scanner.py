import json
import re
from datetime import datetime
from typing import Any, Dict, List, Union

import pytz
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.config import Config
from artemis.fallback_api_cache import FallbackAPICache
from artemis.module_base import ArtemisBase


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class WordPressScanner(ArtemisBase):
    """
    WordPress scanner - checks e.g. whether the verson is secure or whether registration is enabled.
    """

    identity = "wp_scanner"
    filters = [
        {"type": TaskType.WEBAPP.value, "webapp": WebApplication.WORDPRESS.value},
    ]

    def _is_version_latest(self, version: str) -> bool:
        data = json.loads(FallbackAPICache.Urls.WORDPRESS_STABLE_CHECK.value.get().content)

        if version not in data:
            raise Exception(f"Cannot check whether version is latest: {version}")

        return bool(data[version] == "latest")

    def _is_version_old(
        self, version: str, age_threshold_days: int = Config.Modules.WordPressScanner.WORDPRESS_VERSION_AGE_DAYS
    ) -> bool:
        if self._is_version_latest(version):
            return False

        data = json.loads(FallbackAPICache.Urls.WORDPRESS_TAGS.value.get().content)

        for tag in data:
            if tag["ref"] == "refs/tags/" + version:
                tag_data = json.loads(FallbackAPICache.get(tag["object"]["url"], allow_unknown=True).content)
                version_age = datetime.utcnow().replace(tzinfo=pytz.utc) - datetime.fromisoformat(
                    tag_data["committer"]["date"]
                )
                return version_age.days > age_threshold_days
        return True  # If we didn't find the version on the release list, it must be old

    def _is_version_insecure(self, version: str) -> bool:
        data = json.loads(FallbackAPICache.Urls.WORDPRESS_STABLE_CHECK.value.get().content)

        if version not in data:
            raise Exception(f"Cannot check version stability: {version}")

        assert data[version] in ["insecure", "outdated", "latest"]
        # bool() is to silence mypy warning that the == result doesn't have to be bool
        return bool(data[version] == "insecure")

    def scan(self, current_task: Task, url: str) -> None:
        found_problems = []
        result: Dict[str, Union[bool, str, List[Any]]] = {}

        # Check for open registration
        registration_url = f"{url}/wp-login.php?action=register"
        response = self.http_get(registration_url)
        if '<form name="registerform" id="registerform"' in response.text:
            found_problems.append(f"registration is open on {registration_url}")
            result["registration_url"] = registration_url

        # Check if they are running latest patch version
        response = self.http_get(url)
        wp_version = None
        if match := re.search('<meta name="generator" content="WordPress ([0-9]+\\.[0-9]+\\.[0-9]+)', response.text):
            wp_version = match.group(1)
        elif match := re.search("wp-includes/js/wp-embed.min.js\\?ver=([0-9]+\\.[0-9]+\\.[0-9]+)", response.text):
            wp_version = match.group(1)

        if wp_version:
            result["wp_version"] = wp_version
            if self._is_version_insecure(wp_version):
                found_problems.append(f"WordPress {wp_version} is considered insecure")
                result["wp_version_insecure"] = True

            if self._is_version_old(wp_version):
                found_problems.append(f"WordPress {wp_version} is old")
                result["wp_version_old"] = True

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
