#!/usr/bin/env python3
import dataclasses
import os
import random
import string
from difflib import SequenceMatcher
from itertools import product
from typing import IO, List, Set

from karton.core import Task

from artemis import http_requests
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.models import FoundURL
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url
from artemis.utils import is_directory_index


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

EXTENSIONS = ["zip", "tar.gz", "7z", "tar", "gz", "tgz"]
with open(os.path.join(os.path.dirname(__file__), "data", "Common-DB-Backups.txt")) as common_db_backups_file:
    with open(os.path.join(os.path.dirname(__file__), "data", "quickhits.txt")) as quickhits_file:
        FILENAMES_TO_SCAN: Set[str] = set(
            [f"{a}.{b}" for a, b in product(FILENAMES_WITHOUT_EXTENSIONS, EXTENSIONS)]
            + [
                "adminbackups",
                "core",
                "errors",
                ".env",
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
    "<!-- dummy index.html -->",
    "<!DOCTYPE html><title></title>",  # Joomla! placeholder to suppress directory listing
    "*\n!.gitignore",  # Not an interesting .gitignore
]


@dataclasses.dataclass
class BruterResult:
    too_many_urls_detected: bool
    found_urls: List[FoundURL]
    checked_top_paths: List[str]
    checked_random_paths: List[str]


class Bruter(ArtemisBase):
    """
    Tries to find common URLs
    """

    identity = "bruter"
    filters = [
        {"type": TaskType.SERVICE, "service": Service.HTTP},
    ]

    def scan(self, task: Task) -> BruterResult:
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

        random_paths = list(FILENAMES_TO_SCAN)
        random.shuffle(random_paths)
        random_paths = random_paths[: Config.BRUTER_NUM_RANDOM_PATHS_TO_USE]

        top_paths = self.db.get_top_values_for_statistic("bruter", Config.BRUTER_NUM_TOP_PATHS_TO_USE)

        results = {}
        for url in set(random_paths) | set(top_paths):
            try:
                results[url] = http_requests.get(base_url + "/" + url, allow_redirects=Config.BRUTER_FOLLOW_REDIRECTS)
            except Exception:
                pass

        # For downloading URLs, we don't use an existing tool (such as e.g. dirbuster or gobuster) as we
        # need to have a custom logic to filter custom 404 pages and if we used a separate tool, we would
        # not have access to response contents here.

        found_urls = []
        for response_url, response in sorted(results.items()):
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
                found_urls.append(
                    FoundURL(
                        url=response_url,
                        content_prefix=response.content[: Config.CONTENT_PREFIX_SIZE],
                        has_directory_index=is_directory_index(response.content),
                    )
                )

                url = response_url[len(base_url) + 1 :]
                if url in random_paths:
                    self.db.statistic_increase("bruter", url)

                    if is_directory_index(response.content):
                        self.db.statistic_increase("bruter-with-directory-index", url)

        if len(found_urls) > len(FILENAMES_TO_SCAN) * Config.BRUTER_FALSE_POSITIVE_THRESHOLD:
            return BruterResult(
                too_many_urls_detected=True,
                found_urls=[],
                checked_top_paths=top_paths,
                checked_random_paths=random_paths,
            )

        return BruterResult(
            too_many_urls_detected=False,
            found_urls=found_urls,
            checked_top_paths=top_paths,
            checked_random_paths=random_paths,
        )

    def run(self, task: Task) -> None:
        scan_result = self.scan(task)

        if len(scan_result.found_urls) > 0:
            status = TaskStatus.INTERESTING

            found_urls = []
            found_urls_with_directory_index = []
            for item in scan_result.found_urls:
                found_urls.append(item.url)

                if item.has_directory_index:
                    found_urls_with_directory_index.append(item.url)

            status_reason = "Found URLs: " + ", ".join(sorted(found_urls))
            if found_urls_with_directory_index:
                status_reason += " (" + ", ".join(sorted(found_urls_with_directory_index)) + " with directory index)"
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=task, status=status, status_reason=status_reason, data=dataclasses.asdict(scan_result)
        )


if __name__ == "__main__":
    Bruter().loop()
