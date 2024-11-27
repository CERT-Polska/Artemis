from typing import Optional

import bs4
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.modules.base.base_newer_version_comparer import (
    BaseNewerVersionComparerModule,
)


class DrupalScannerException(Exception):
    pass


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class DrupalScanner(BaseNewerVersionComparerModule):
    """
    Drupal scanner - checks whether the version is obsolete.
    """

    identity = "drupal_scanner"
    filters = [
        {"type": TaskType.WEBAPP.value, "webapp": WebApplication.DRUPAL.value},
    ]
    software_name = "drupal"

    # Some homepages are big - let's override the default downloaded content size because
    # we want to identify Drupal version based on a script which is at the bottom.
    DOWNLOADED_CONTENT_PREFIX_SIZE = 5 * 1024 * 1024

    def run(self, current_task: Task) -> None:
        url = current_task.get_payload("url")
        response = self.http_get(url, max_size=DrupalScanner.DOWNLOADED_CONTENT_PREFIX_SIZE)
        soup = bs4.BeautifulSoup(response.content)

        version: Optional[str] = None
        for script in soup.findAll("script"):
            if "/core/misc/drupal.js?v=" in script.get("src", ""):
                version = script["src"].split("=")[1]

        if version:
            is_version_obsolete = super().is_version_obsolete(
                version,
            )
        else:
            is_version_obsolete = None

        result = {
            "version": version,
            "is_version_obsolete": is_version_obsolete,
        }

        if not version:
            raise DrupalScannerException(f"Unable to obtain Drupal version for {url}")

        if version and is_version_obsolete:
            found_problems = [f"Drupal version {version} on {url} is obsolete"]
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
