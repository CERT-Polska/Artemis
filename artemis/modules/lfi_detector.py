import random
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import more_itertools
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.crawling import get_links_and_resources_on_same_domain
from artemis.http_requests import HTTPResponse
from artemis.module_base import ArtemisBase
from artemis.modules.data.static_extensions import STATIC_EXTENSIONS
from artemis.task_utils import get_target_url
from artemis.modules.data.lfi_detector_data import LFI_PARAMS, LFI_PAYLOADS


class LFIFindings(Enum):
    LFI_VULNERABILITY = "lfi_vulnerability"


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.HIGH)
class LFIDetector(ArtemisBase):
    """
    Module for detecting Local File Inclusion (LFI) vulnerabilities.
    """

    identity = "lfi_detector"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _strip_query_string(self, url: str) -> str:
        url_parsed = urlparse(url)
        return urlunparse(url_parsed._replace(query="", fragment=""))

    def create_url_with_batch_payload(self, url: str, param_batch: Tuple[str, ...], payload: str) -> str:
        assignments = {key: payload for key in param_batch}
        concatenation = "&" if self.is_url_with_parameters(url) else "?"
        return f"{url}{concatenation}" + "&".join([f"{key}={value}" for key, value in assignments.items()])

    def is_url_with_parameters(self, url: str) -> bool:
        return bool(re.search(r"/?/*=", url))

    def contains_lfi_indicator(self, response: HTTPResponse) -> Optional[str]:
        """Check if the response contains indicators of LFI."""
        indicators = [
            ("root:x:", "/etc/passwd"),
            ("[extensions]", "php.ini"),
            ("<?php", "PHP file"),
            ("Windows Registry Editor", "Windows .ini file"),
        ]
        for indicator, description in indicators:
            if indicator in response.content:
                self.log.debug(f"Matched LFI indicator: {description}")
                return description
        return None

    def scan(self, urls: List[str], task: Task) -> List[Dict[str, Any]]:
        """Scan URLs for LFI vulnerabilities."""
        message: List[Dict[str, Any]] = []

        for current_url in urls:
            for param_batch in more_itertools.batched(LFI_PARAMS, 50):  # Example parameters
                for payload in LFI_PAYLOADS:
                    url_with_payload = self.create_url_with_batch_payload(current_url, param_batch, payload)
                    response = self.http_get(url_with_payload)

                    if indicator := self.contains_lfi_indicator(response):
                        message.append(
                            {
                                "url": url_with_payload,
                                "headers": {},
                                "matched_indicator": indicator,
                                "statement": "It appears that this URL is vulnerable to LFI",
                                "code": LFIFindings.LFI_VULNERABILITY.value,
                            }
                        )
                        if Config.Modules.LFIDetector.LFI_STOP_ON_FIRST_MATCH:
                            return message

        return message

    def run(self, current_task: Task) -> None:
        """Run the LFI detection module."""
        if self.check_connection_to_base_url_and_save_error(current_task):
            url = get_target_url(current_task)

            links = get_links_and_resources_on_same_domain(url)
            links.append(url)
            links = list(set(links) | set([self._strip_query_string(link) for link in links]))

            links = [
                link.split("#")[0]
                for link in links
                if not any(link.split("?")[0].lower().endswith(extension) for extension in STATIC_EXTENSIONS)
            ]

            random.shuffle(links)

            message = self.scan(urls=links[:25], task=current_task)

            if message:
                status = TaskStatus.INTERESTING
                status_reason = ", ".join([m["statement"] for m in message])
            else:
                status = TaskStatus.OK
                status_reason = None

            data = {"result": message, "statements": {e.value: e.name for e in LFIFindings}}

            self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=data)


if __name__ == "__main__":
    LFIDetector().loop()