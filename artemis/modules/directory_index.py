#!/usr/bin/env python3

import dataclasses
import random
import urllib.parse
from typing import List

from bs4 import BeautifulSoup
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.models import FoundURL
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url
from artemis.utils import is_directory_index

MAX_DIRS_PER_PATH = 4
MAX_TESTS_PER_URL = 20
S3_BASE_DOMAIN = "s3.amazonaws.com"


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class DirectoryIndex(ArtemisBase):
    """
    Detects directory index enabled on the server by checking paths mentioned in the home page source (e.g. with <link href="/styles/..." ...>).
    """

    identity = "directory_index"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def scan(self, base_url: str) -> List[FoundURL]:
        response = self.http_get(base_url)
        soup = BeautifulSoup(response.content, "html.parser")
        original_base_url_parsed = urllib.parse.urlparse(base_url)

        path_candidates = set()
        for tag in soup.find_all():
            new_url = None
            for attribute in ["src", "href"]:
                if attribute not in tag.attrs:
                    continue

                new_url = urllib.parse.urljoin(base_url, tag[attribute])
                new_url_parsed = urllib.parse.urlparse(new_url)

                if new_url_parsed.netloc.endswith(S3_BASE_DOMAIN):
                    path = urllib.parse.urljoin(new_url_parsed.path, ".")
                    for i in range(MAX_DIRS_PER_PATH):
                        path_candidates.add("https://" + new_url_parsed.netloc + path)
                        path = urllib.parse.urljoin(path, "..")
                        if path == "" or path == "/":
                            if new_url_parsed.netloc != S3_BASE_DOMAIN:
                                path_candidates.add("https://" + new_url_parsed.netloc + path)
                            break

                if original_base_url_parsed.netloc == new_url_parsed.netloc:
                    path = urllib.parse.urljoin(new_url_parsed.path, ".")

                    for i in range(MAX_DIRS_PER_PATH):
                        path_candidates.add(path)
                        path = urllib.parse.urljoin(path, "..")
                        if path == "" or path == "/":
                            break

        path_candidates_list = list(path_candidates)
        random.shuffle(path_candidates_list)
        path_candidates_list = path_candidates_list[:MAX_TESTS_PER_URL]
        results = []
        for path_candidate in path_candidates_list:
            url = urllib.parse.urljoin(base_url, path_candidate)
            response = self.http_get(url)
            content = response.content
            if is_directory_index(content):
                results.append(
                    FoundURL(
                        url=url,
                        content_prefix=content[: Config.Miscellaneous.CONTENT_PREFIX_SIZE],
                        has_directory_index=True,
                    )
                )
        return results

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"directory index scanning {url}")
        found_urls = self.scan(url)

        if len(found_urls) > 0:
            status = TaskStatus.INTERESTING
            status_reason = "Found directories with index enabled: " + ", ".join(
                sorted([item.url for item in found_urls])
            )
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data=[dataclasses.asdict(item) for item in found_urls],
        )


if __name__ == "__main__":
    DirectoryIndex().loop()
