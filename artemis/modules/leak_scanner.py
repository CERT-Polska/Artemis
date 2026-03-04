#!/usr/bin/env python3
import urllib.parse
from collections import deque
from typing import Any, Callable, Dict, List, Set, Tuple

import requests
import xray
from bs4 import BeautifulSoup
from karton.core import Task

from artemis import http_requests, load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url
from artemis.utils import check_output_log_on_error

# Document extensions to scan. This list will grow as more check types
# are added (e.g. .docx, .xlsx, .pptx for metadata leaks).
DOCUMENT_EXTENSIONS = [".pdf"]

# Type for a check function: takes file bytes, returns list of findings.
CheckFunction = Callable[[bytes], List[Dict[str, Any]]]


def _check_bad_redaction(file_bytes: bytes) -> List[Dict[str, Any]]:
    """Check a PDF for improperly redacted/censored content using x-ray."""
    findings = xray.inspect(file_bytes)
    leaked_items: List[Dict[str, Any]] = []
    if findings:
        for page_num, items in findings.items():
            for item in items:
                leaked_items.append(
                    {
                        "page": page_num,
                        "bbox": list(item["bbox"]),
                        "text": item["text"],
                    }
                )
    return leaked_items


# Registry of checks to run against downloaded documents.
# Each entry is (check_name, applicable_extensions, check_function).
# To add a new check, append to this list.
DOCUMENT_CHECKS: List[Tuple[str, List[str], CheckFunction]] = [
    ("bad_redaction", [".pdf"], _check_bad_redaction),
]


def _is_document_url(url: str) -> bool:
    """Check if a URL points to a document we want to scan."""
    path_lower = urllib.parse.urlparse(url).path.lower()
    return any(path_lower.endswith(ext) for ext in DOCUMENT_EXTENSIONS)


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class LeakScanner(ArtemisBase):
    """
    Scans websites for documents with data leaks such as bad censorship/redaction
    attempts (e.g. black rectangles that can be removed to reveal hidden text).
    Crawls the website up to a configurable depth to discover document URLs.
    """

    identity = "leak_scanner"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _discover_documents_via_crawl(self, base_url: str, max_documents: int) -> List[str]:
        """BFS crawl the website to discover document URLs.

        Follows same-domain links up to LEAK_SCANNER_CRAWL_DEPTH levels,
        visiting at most LEAK_SCANNER_MAX_PAGES_TO_CRAWL pages.
        """
        max_depth = Config.Modules.LeakScanner.LEAK_SCANNER_CRAWL_DEPTH
        max_pages = Config.Modules.LeakScanner.LEAK_SCANNER_MAX_PAGES_TO_CRAWL

        base_hostname = urllib.parse.urlparse(base_url).hostname

        visited: Set[str] = set()
        document_urls: List[str] = []
        queue: deque = deque([(base_url, 0)])
        visited.add(base_url)
        pages_crawled = 0

        while queue and pages_crawled < max_pages and len(document_urls) < max_documents:
            current_url, depth = queue.popleft()

            if _is_document_url(current_url):
                continue

            pages_crawled += 1

            try:
                response = http_requests.get(current_url)
            except requests.exceptions.RequestException:
                continue

            if response.status_code != 200:
                continue

            soup = BeautifulSoup(response.text, "html.parser")

            for tag in soup.find_all():
                for attribute in ["src", "href"]:
                    if attribute not in tag.attrs:
                        continue

                    new_url = urllib.parse.urljoin(current_url, tag[attribute])
                    new_url = new_url.split("#")[0]
                    new_url_parsed = urllib.parse.urlparse(new_url)

                    if new_url_parsed.hostname != base_hostname:
                        continue

                    if new_url in visited:
                        continue
                    visited.add(new_url)

                    if _is_document_url(new_url):
                        document_urls.append(new_url)
                        if len(document_urls) >= max_documents:
                            return document_urls
                    elif depth + 1 <= max_depth:
                        queue.append((new_url, depth + 1))

        return document_urls

    def _discover_documents_via_gau(self, domain: str) -> Set[str]:
        """Query gau for archived document URLs from Wayback Machine and Common Crawl."""
        try:
            result = check_output_log_on_error(["gau"], self.log, input=domain.encode("idna"))
            urls: Set[str] = set()
            for line in result.decode().splitlines():
                line = line.strip()
                if line and _is_document_url(line):
                    urls.add(line)
            return urls
        except Exception:
            self.log.exception(f"Unable to obtain document URLs from gau for {domain}")
            return set()

    def _discover_document_urls(self, base_url: str) -> List[str]:
        """Discover document URLs using both BFS crawling and gau."""
        max_documents = Config.Modules.LeakScanner.LEAK_SCANNER_MAX_DOCUMENTS_TO_CHECK
        base_hostname = urllib.parse.urlparse(base_url).hostname

        crawl_urls = self._discover_documents_via_crawl(base_url, max_documents)
        seen: Set[str] = set(crawl_urls)
        document_urls = list(crawl_urls)

        if base_hostname:
            gau_urls = self._discover_documents_via_gau(base_hostname)
            for url in gau_urls:
                if url not in seen and len(document_urls) < max_documents:
                    parsed = urllib.parse.urlparse(url)
                    if parsed.hostname == base_hostname:
                        document_urls.append(url)
                        seen.add(url)

        return document_urls

    def _scan_document(self, document_url: str) -> Dict[str, Any]:
        """Download a document and run all applicable checks against it."""
        response = self.http_get(
            document_url,
            max_size=Config.Modules.LeakScanner.LEAK_SCANNER_MAX_DOCUMENT_SIZE_BYTES,
        )

        if response.status_code != 200:
            self.log.info(f"Skipping {document_url}: HTTP {response.status_code}")
            return {}

        file_bytes = response.content_bytes
        path_lower = urllib.parse.urlparse(document_url).path.lower()

        all_findings: Dict[str, List[Dict[str, Any]]] = {}
        for check_name, applicable_extensions, check_fn in DOCUMENT_CHECKS:
            if not any(path_lower.endswith(ext) for ext in applicable_extensions):
                continue
            try:
                findings = check_fn(file_bytes)
            except Exception as e:
                self.log.warning(f"Check '{check_name}' failed on {document_url}: {e}")
                continue
            if findings:
                all_findings[check_name] = findings

        if all_findings:
            return {"url": document_url, "findings": all_findings}
        return {}

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"LeakScanner scanning {url}")

        document_urls = self._discover_document_urls(url)
        self.log.info(f"Found {len(document_urls)} document URL(s) on {url}")

        documents_with_findings: List[Dict[str, Any]] = []
        for document_url in document_urls:
            self.log.info(f"Scanning document: {document_url}")
            result = self._scan_document(document_url)
            if result:
                documents_with_findings.append(result)

        if documents_with_findings:
            status = TaskStatus.INTERESTING
            num_total_findings = sum(
                len(items)
                for doc in documents_with_findings
                for items in doc["findings"].values()
            )
            status_reason = (
                f"Found {num_total_findings} leaked sensitive data item(s) "
                f"in {len(documents_with_findings)} document(s) with issues"
            )
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={
                "documents_checked": len(document_urls),
                "documents_with_findings": documents_with_findings,
            },
        )


if __name__ == "__main__":
    LeakScanner().loop()
