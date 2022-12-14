#!/usr/bin/env python3

import random
import urllib.parse
from typing import List

from bs4 import BeautifulSoup
from karton.core import Task

from artemis import http_requests
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisSingleTaskBase
from artemis.task_utils import get_target_url

PATHS: List[str] = ["/backup/", "/backups/", "/_vti_bin/", "/wp-content/", "/wp-includes/"]
MAX_DIRS_PER_PATH = 4
MAX_TESTS_PER_URL = 20
S3_BASE_DOMAIN = "s3.amazonaws.com"


class DirectoryIndex(ArtemisSingleTaskBase):
    """
    Detects directory index enabled on the server
    """

    identity = "directory_index"
    filters = [
        {"type": TaskType.SERVICE, "service": Service.HTTP},
    ]

    def scan(self, url: str) -> List[str]:
        response = http_requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        original_url_parsed = urllib.parse.urlparse(url)

        path_candidates = set(PATHS)
        for tag in soup.find_all():
            new_url = None
            for attribute in ["src", "href"]:
                if attribute not in tag.attrs:
                    continue

                new_url = urllib.parse.urljoin(url, tag[attribute])
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

                if original_url_parsed.netloc == new_url_parsed.netloc:
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
            response = http_requests.get(urllib.parse.urljoin(url, path_candidate))
            content = response.content.decode("utf-8", errors="ignore")
            if (
                "Index of /" in content
                or "ListBucketResult" in content
                or "<title>directory listing" in content.lower()
                or "<title>index of" in content.lower()
            ):
                if (
                    path_candidate not in Config.NOT_INTERESTING_PATHS
                    and path_candidate + "/" not in Config.NOT_INTERESTING_PATHS
                ):
                    results.append(path_candidate)
        return sorted(results)

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"directory index scanning {url}")
        found_dirs_with_index = self.scan(url)

        if len(found_dirs_with_index) > 0:
            status = TaskStatus.INTERESTING
            status_reason = "Found directories with index enabled: " + ", ".join(sorted(found_dirs_with_index))
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=current_task, status=status, status_reason=status_reason, data=found_dirs_with_index
        )


if __name__ == "__main__":
    DirectoryIndex().loop()
