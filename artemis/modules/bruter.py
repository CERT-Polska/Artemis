#!/usr/bin/env python3
import os
import random
import string
from difflib import SequenceMatcher
from itertools import product
from typing import IO, List, Set

import requests
from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.http import download_urls
from artemis.module_base import ArtemisHTTPBase


def read_paths_from_file(file: IO[str]) -> List[str]:
    return [line.strip().lstrip("/") for line in file if not line.startswith("#")]


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
        FILENAMES_TO_SCAN: Set[str] = set(
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
            + read_paths_from_file(common_db_backups_file)
            + read_paths_from_file(quickhits_file)
        )

with open(os.path.join(os.path.dirname(__file__), "data", "ignore_paths.txt")) as ignore_paths_file:
    IGNORE_PATHS_ORIGINAL = read_paths_from_file(ignore_paths_file)
    IGNORE_PATHS = set(IGNORE_PATHS_ORIGINAL) | {path + "/" for path in IGNORE_PATHS_ORIGINAL}
    FILENAMES_TO_SCAN = FILENAMES_TO_SCAN - IGNORE_PATHS

IGNORED_CONTENTS = [
    "",
    "<!DOCTYPE html><title></title>",  # Joomla! placeholder to suppress directory listing
    "*\n!.gitignore",  # Not an interesting .gitignore
]


class Bruter(ArtemisHTTPBase):
    """
    Tries to find common files
    """

    identity = "bruter"
    filters = [
        {"type": TaskType.SERVICE, "service": Service.HTTP},
    ]

    def scan(self, url: str) -> List[str]:
        found_files = set()
        # random endpoint to filter out custom 404 pages
        dummy_random_token = "".join(random.choices(string.ascii_letters + string.digits, k=16))
        dummy_url = url + "/" + dummy_random_token
        dummy = requests.get(dummy_url, verify=False, timeout=5)

        urls = [f"{url}/{file}" for file in FILENAMES_TO_SCAN]
        # For downloading URLs, we don't use an existing tool (such as e.g. dirbuster or gobuster) as we
        # need to have a custom logic to filter custom 404 pages and if we used a separate tool, we would
        # not have access to response contents here.
        results = download_urls(urls)
        for response_url, response in results.items():
            if (
                response.status_code == 200
                and response.content
                and "<center><h1>40" not in response.content
                and "Error 403" not in response.content
                and "<title>Access forbidden!</title>" not in response.content
                and response.content.strip() not in IGNORED_CONTENTS
                and SequenceMatcher(None, response.content, dummy.content).quick_ratio() < 0.8
            ):
                found_files.add(response_url)
        return sorted(list(found_files))

    def run(self, current_task: Task) -> None:
        url = self.get_target_url(current_task)
        self.log.info(f"bruter scanning {url}")
        found_files = self.scan(url)

        if len(found_files) > 0:
            status = TaskStatus.INTERESTING
            status_reason = "Found files: " + ", ".join(sorted(found_files))
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=found_files)


if __name__ == "__main__":
    Bruter().loop()
