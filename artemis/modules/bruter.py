#!/usr/bin/env python3
import os
import random
import string
from difflib import SequenceMatcher
from itertools import product
from typing import IO, List, Set, Tuple

from karton.core import Task

from artemis import http_requests
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.modules.utils.directory_index import is_directory_index
from artemis.task_utils import get_target_url


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
    "pack",
    "backup",
    "old",
    "sql",
    "www",
]

EXTENSIONS = ["zip", "rar", "7z", "tar", "gz", "tgz"]
with open(os.path.join(os.path.dirname(__file__), "data", "Common-DB-Backups.txt")) as common_db_backups_file:
    with open(os.path.join(os.path.dirname(__file__), "data", "quickhits.txt")) as quickhits_file:
        FILENAMES_TO_SCAN: Set[str] = set(
            [f"{a}.{b}" for a, b in product(FILENAMES_WITHOUT_EXTENSIONS, EXTENSIONS)]
            + [
                "adminbackups",
                "core",
                "errors",
                ".env",
                ".gitignore",
                ".htaccess",
                ".htpasswd",
                ".ssh/id_rsa",
                "server-status/",
                "app_dev.php",
                "TEST",
                "_vti_bin",
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


class Bruter(ArtemisBase):
    """
    Tries to find common URLs
    """

    identity = "bruter"
    filters = [
        {"type": TaskType.SERVICE, "service": Service.HTTP},
    ]

    def scan(self, task: Task) -> Tuple[List[str], List[str]]:
        """
        Brute-forces URLs. Returns two lists: all found URLs and the ones detected to be
        a directory index.
        """
        base_url = get_target_url(task)

        self.log.info(f"bruter scanning {base_url}")

        # random endpoint to filter out custom 404 pages
        dummy_random_token = "".join(random.choices(string.ascii_letters + string.digits, k=16))
        dummy_url = base_url + "/" + dummy_random_token
        try:
            dummy_content = http_requests.get(dummy_url).content
        except Exception:
            dummy_content = ""

        urls: List[str] = []

        for file in set(FILENAMES_TO_SCAN):
            url = f"{base_url}/{file}"
            urls.append(url)

        # For downloading URLs, we don't use an existing tool (such as e.g. dirbuster or gobuster) as we
        # need to have a custom logic to filter custom 404 pages and if we used a separate tool, we would
        # not have access to response contents here.
        results = {}
        for url in urls:
            try:
                results[url] = http_requests.get(url)
            except Exception:
                pass

        found_urls = set()
        found_urls_with_directory_index = set()
        for response_url, response in results.items():
            if response.status_code != 200:
                continue

            if (
                response.content
                and "<center><h1>40" not in response.content
                and "Error 403" not in response.content
                and "<title>Access forbidden!</title>" not in response.content
                and response.content.strip() not in IGNORED_CONTENTS
                and SequenceMatcher(None, response.content, dummy_content).quick_ratio() < 0.8
            ):
                found_urls.add(response_url)

                if is_directory_index(response.content):
                    found_urls_with_directory_index.add(response_url)

        if len(found_urls) > len(FILENAMES_TO_SCAN) * Config.BRUTER_FALSE_POSITIVE_THRESHOLD:
            return [], []

        return sorted(list(found_urls)), sorted(list(found_urls_with_directory_index))

    def run(self, task: Task) -> None:
        found_urls, found_urls_with_directory_index = self.scan(task)

        if len(found_urls) > 0:
            status = TaskStatus.INTERESTING
            status_reason = "Found URLs: " + ", ".join(found_urls)
            if found_urls_with_directory_index:
                status_reason += " (" + ", ".join(found_urls_with_directory_index) + " with directory index)"
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=task,
            status=status,
            status_reason=status_reason,
            data={
                "found_urls": found_urls,
                "found_urls_with_directory_index": found_urls_with_directory_index,
            },
        )


if __name__ == "__main__":
    Bruter().loop()
