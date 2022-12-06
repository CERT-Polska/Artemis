#!/usr/bin/env python3
import os
import random
import string
from difflib import SequenceMatcher
from itertools import product
from typing import Dict, List, Set

import requests
from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.http import download_urls
from artemis.module_base_multiple_tasks import ArtemisMultipleTasksBase
from artemis.task_utils import get_target_url

FILENAMES_WITHOUT_EXTENSIONS = [
    "admin_backup",
    "admin.backup",
    "admin_bkp",
    "admin.bkp",
    "admin_old",
    "admin.old",
    "panel",
    "backup",
    "old",
    "sql",
]
EXTENSIONS = ["zip", "rar", "7z", "tar", "gz", "tgz"]
with open(os.path.join(os.path.dirname(__file__), "data", "Common-DB-Backups.txt")) as common_db_backups_file:
    with open(os.path.join(os.path.dirname(__file__), "data", "quickhits.txt")) as quickhits_file:
        FILENAMES_TO_SCAN: List[str] = (
            [f"{a}.{b}" for a, b in product(FILENAMES_WITHOUT_EXTENSIONS, EXTENSIONS)]
            + [
                ".env",
                ".gitignore",
                ".htaccess",
                ".htpasswd",
                ".ssh/id_rsa",
                "server-status/",
                "app_dev.php",
            ]
            + [line.strip().lstrip("/") for line in common_db_backups_file if not line.startswith("#")]
            + [line.strip().lstrip("/") for line in quickhits_file if not line.startswith("#")]
        )


class Bruter(ArtemisMultipleTasksBase):
    """
    Tries to find common files
    """

    identity = "bruter"
    filters = [
        {"type": TaskType.SERVICE, "service": Service.HTTP},
    ]

    def scan(self, tasks: List[Task]) -> Dict[str, List[str]]:
        """
        Brute-forces URLs. Returns a dict: task uid -> list of found URLs.
        """
        base_urls = {task.uid: get_target_url(task) for task in tasks}

        self.log.info(f"bruter scanning {', '.join(base_urls.values())}")

        dummy_contents = {}
        for task_uid, base_url in base_urls.items():
            # random endpoint to filter out custom 404 pages
            dummy_random_token = "".join(random.choices(string.ascii_letters + string.digits, k=16))
            dummy_url = base_url + "/" + dummy_random_token
            try:
                dummy_contents[task_uid] = requests.get(dummy_url, verify=False, timeout=5).content.decode("utf-8")
            except Exception:
                dummy_contents[task_uid] = ""

        urls: List[str] = []
        urls_to_task_uid_mapping = {}

        for file in set(FILENAMES_TO_SCAN):
            for task_uid, base_url in base_urls.items():
                url = f"{base_url}/{file}"
                urls.append(url)
                urls_to_task_uid_mapping[url] = task_uid

        # For downloading URLs, we don't use an existing tool (such as e.g. dirbuster or gobuster) as we
        # need to have a custom logic to filter custom 404 pages and if we used a separate tool, we would
        # not have access to response contents here.
        results = download_urls(urls)

        found_files: Dict[str, Set[str]] = {}
        for response_url, response in results.items():
            task_uid = urls_to_task_uid_mapping[response_url]
            base_url = base_urls[task_uid]

            if (
                response.status_code == 200
                and response.content
                and "<center><h1>40" not in response.content
                and "Error 403" not in response.content
                and SequenceMatcher(None, response.content, dummy_contents[task_uid]).quick_ratio() < 0.8
            ):
                if task_uid not in found_files:
                    found_files[task_uid] = set()

                found_files[task_uid].add(response_url[len(base_url) + 1 :])

        found_files_as_lists = {}
        for key in found_files.keys():
            found_files_as_lists[key] = sorted(list(found_files[key]))
        return found_files_as_lists

    def run_multiple(self, tasks: List[Task]) -> None:
        found_files_per_task_uid = self.scan(tasks)

        for task in tasks:
            found_files = found_files_per_task_uid.get(task.uid, [])

            if len(found_files) > 0:
                status = TaskStatus.INTERESTING
                status_reason = "Found files: " + ", ".join(sorted(found_files))
            else:
                status = TaskStatus.OK
                status_reason = None

            self.db.save_task_result(task=task, status=status, status_reason=status_reason, data=found_files)


if __name__ == "__main__":
    Bruter().loop()
