import datetime
import json
import subprocess
import tempfile
from pathlib import Path

import bs4
from karton.core import Task

from artemis import http_requests
from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.module_base import ArtemisBase


class DrupalScanner(ArtemisBase):
    """
    Drupal scanner - checks whether the version is supported.
    """

    identity = "drupal_scanner"
    filters = [
        {"type": TaskType.WEBAPP.value, "webapp": WebApplication.DRUPAL.value},
    ]

    # Some homepages are big - let's override the default downloaded content size because
    # we want to identify Drupal version based on the script which is at the bottom.
    DOWNLOADED_CONTENT_PREFIX_SIZE = 5 * 1024 * 1024

    def __init__(self, *args, **kwargs):  # type: ignore
        super().__init__(*args, **kwargs)

        release_expiry_data_folder = tempfile.mkdtemp()
        subprocess.call(["git", "clone", "https://github.com/endoflife-date/release-data", release_expiry_data_folder])
        release_expiry_data_path = Path(release_expiry_data_folder) / "releases" / "drupal.json"
        with open(release_expiry_data_path, "r") as f:
            self.release_expiry_data = json.load(f)

    def is_version_obsolete(self, version: str) -> bool:
        if version not in self.release_expiry_data:
            return True  # If it's not even in the expiry data, let's consider it obsolete
        return datetime.datetime.strptime(self.release_expiry_data[version], "%Y-%m-%d") < datetime.datetime.now()

    def run(self, current_task: Task) -> None:
        url = current_task.get_payload("url")
        response = http_requests.get(url, max_size=DrupalScanner.DOWNLOADED_CONTENT_PREFIX_SIZE)
        soup = bs4.BeautifulSoup(response.content)

        version = None
        for script in soup.findAll("script"):
            if script.get("src", "").startswith("/core/misc/drupal.js?v="):
                version = script["src"].split("=")[1]

        result = {
            "version": version,
            "is_version_obsolete": self.is_version_obsolete(version) if version else None,
        }

        if version and self.is_version_obsolete(version):
            found_problems = [f"Drupal version {version} on {url} is obsolete"]
        elif not version:
            found_problems = [f"Unable to obtain Drupal version for {url}"]
        else:
            found_problems = []

        if found_problems:
            status = TaskStatus.INTERESTING
            status_reason = "Found problems: " + ", ".join(sorted(found_problems))
        else:
            status = TaskStatus.OK
            status_reason = None
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    DrupalScanner().loop()  # type: ignore
