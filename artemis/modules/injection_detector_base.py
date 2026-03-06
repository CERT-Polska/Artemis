import random
import re
from abc import abstractmethod
from typing import Any, Dict, List
from urllib.parse import urlparse, urlunparse

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.crawling import get_links_and_resources_on_same_domain
from artemis.module_base import ArtemisBase
from artemis.modules.data.static_extensions import STATIC_EXTENSIONS
from artemis.task_utils import get_target_url


class InjectionDetectorBase(ArtemisBase):
    """
    Base class for injection detection modules (LFI, SQL injection, etc.).

    Subclasses must define:
      - identity (str): unique karton identity
      - scan(urls, task): scanning logic returning a list of finding dicts
      - create_status_reason(messages): format messages into a status reason string
      - create_data(messages): build the data dict saved with the task result
    """

    num_retries = Config.Miscellaneous.SLOW_MODULE_NUM_RETRIES
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    # --- shared utility methods ---

    @staticmethod
    def _strip_query_string(url: str) -> str:
        url_parsed = urlparse(url)
        return urlunparse(url_parsed._replace(query="", fragment=""))

    @staticmethod
    def is_url_with_parameters(url: str) -> bool:
        return bool(re.search(r"/?/*=", url))

    def create_url_with_batch_payload(self, url: str, param_batch: Any, payload: str) -> str:
        assignments = {key: payload for key in param_batch}
        concatenation = "&" if self.is_url_with_parameters(url) else "?"
        return f"{url}{concatenation}" + "&".join([f"{key}={value}" for key, value in assignments.items()])

    def _collect_urls(self, url: str) -> List[str]:
        """Gather, deduplicate, filter and shuffle URLs to scan."""
        links = get_links_and_resources_on_same_domain(url)
        links.append(url)
        links = list(set(links) | set([self._strip_query_string(link) for link in links]))

        links = [
            link.split("#")[0]
            for link in links
            if not any(link.split("?")[0].lower().endswith(extension) for extension in STATIC_EXTENSIONS)
        ]

        random.shuffle(links)
        return links[: Config.Miscellaneous.MAX_URLS_TO_SCAN]

    # --- hooks for subclasses ---

    def _pre_run_check(self, current_task: Task) -> bool:
        """Override to add pre-run checks. Return False to skip scanning."""
        return True

    @abstractmethod
    def scan(self, urls: List[str], task: Task) -> List[Dict[str, Any]]:
        """Scan the given URLs and return a list of finding dicts."""
        ...

    @abstractmethod
    def create_status_reason(self, messages: List[Dict[str, Any]]) -> str:
        """Build a human-readable status reason from the scan messages."""
        ...

    @abstractmethod
    def create_data(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build the data payload to save with the task result."""
        ...

    # --- template run method ---

    def run(self, current_task: Task) -> None:
        if not self._pre_run_check(current_task):
            return

        url = get_target_url(current_task)
        urls = self._collect_urls(url)

        messages = self.scan(urls=urls, task=current_task)

        if messages:
            status = TaskStatus.INTERESTING
            status_reason = self.create_status_reason(messages)
        else:
            status = TaskStatus.OK
            status_reason = None

        data = self.create_data(messages)
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=data)
