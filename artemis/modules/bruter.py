#!/usr/bin/env python3
import dataclasses
import os
import random
import string
from difflib import SequenceMatcher
from typing import IO, List, Set

from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.models import FoundURL
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url
from artemis.utils import is_directory_index


def read_paths_from_file(file: IO[str]) -> List[str]:
    return [line.strip().lstrip("/") for line in file if not line.startswith("#")]


CHOSEN_BRUTER_LISTS_PATH = os.path.join(
    os.path.dirname(__file__), "data", "bruter", "lists", Config.Modules.Bruter.BRUTER_FILE_LIST
)

FILENAMES_TO_SCAN: Set[str] = set()

if Config.Modules.Bruter.BRUTER_FILE_LIST not in ["full", "short"]:
    raise Exception(
        "There are two possible bruter file list: short and full, not %s" % Config.Modules.Bruter.BRUTER_FILE_LIST
    )

for file_name in os.listdir(CHOSEN_BRUTER_LISTS_PATH):
    with open(os.path.join(CHOSEN_BRUTER_LISTS_PATH, file_name)) as f:
        for item in read_paths_from_file(f):
            FILENAMES_TO_SCAN.add(item)


IGNORED_CONTENTS = [
    "",
    "<!-- dummy index.html -->",
    "<!DOCTYPE html><title></title>",  # Joomla! placeholder to suppress directory listing
    "*\n!.gitignore",  # Not an interesting .gitignore
]


@dataclasses.dataclass
class BruterResult:
    content_404: str
    too_many_urls_detected: bool
    found_urls: List[FoundURL]
    checked_paths: List[str]


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class Bruter(ArtemisBase):
    """
    Brute-forces common paths such as /index.php.bak. Tries commonly found paths on each target and experiments with random other paths
    to dynamically update the common paths list.
    """

    identity = "bruter"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def scan(self, task: Task) -> BruterResult:
        """
        Brute-forces URLs. Returns two lists: all found URLs and the ones detected to be
        a directory index.
        """
        base_url = get_target_url(task)

        # random endpoint to filter out custom 404 pages
        dummy_random_token = "".join(random.choices(string.ascii_letters + string.digits, k=16))
        dummy_url = base_url + "/" + dummy_random_token
        try:
            dummy_content = self.http_get(dummy_url).content
        except Exception:
            dummy_content = ""

        self.log.info(f"bruter scanning {base_url}: {len(FILENAMES_TO_SCAN)} paths to scan")

        results = {}
        for i, url in enumerate(FILENAMES_TO_SCAN):
            self.log.info(f"bruter url {i}/{len(FILENAMES_TO_SCAN)}: {url}")
            try:
                full_url = base_url + "/" + url
                results[full_url] = self.http_get(
                    full_url, allow_redirects=Config.Modules.Bruter.BRUTER_FOLLOW_REDIRECTS
                )
            except Exception:
                pass

        self.log.info("bruter finished")
        # For downloading URLs, we don't use an existing tool (such as e.g. dirbuster or gobuster) as we
        # need to have a custom logic to filter custom 404 pages and if we used a separate tool, we would
        # not have access to response contents here.

        found_urls = []
        for response_url, response in sorted(results.items()):
            if response.status_code != 200:
                continue

            filtered_content = (
                "Error 403" in response.content
                or response.content.strip() in IGNORED_CONTENTS
                or SequenceMatcher(None, response.content, dummy_content).quick_ratio() >= 0.8
            )

            if not filtered_content:
                found_urls.append(
                    FoundURL(
                        url=response_url,
                        content_prefix=response.content[: Config.Miscellaneous.CONTENT_PREFIX_SIZE],
                        has_directory_index=is_directory_index(response.content),
                    )
                )

        if len(found_urls) > len(FILENAMES_TO_SCAN) * Config.Modules.Bruter.BRUTER_FALSE_POSITIVE_THRESHOLD:
            return BruterResult(
                content_404=dummy_content,
                too_many_urls_detected=True,
                found_urls=[],
                checked_paths=list(FILENAMES_TO_SCAN),
            )

        for found_url in found_urls:
            url = found_url.url[len(base_url) + 1 :]

            new_task = Task(
                {
                    "type": TaskType.URL,
                },
                payload={
                    "url": found_url.url,
                    "content": results[found_url.url].content,
                },
            )
            self.add_task(task, new_task)

        return BruterResult(
            content_404=dummy_content,
            too_many_urls_detected=False,
            found_urls=found_urls,
            checked_paths=list(FILENAMES_TO_SCAN),
        )

    def run(self, task: Task) -> None:
        if not self.check_connection_to_base_url_and_save_error(task):
            return

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
