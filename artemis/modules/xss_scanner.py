"""XSS Scanner module for detecting Cross-Site Scripting vulnerabilities."""
import html
import random
import re
import urllib.parse
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlunparse

from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.crawling import (
    get_injectable_parameters,
    get_links_and_resources_on_same_domain,
)
from artemis.http_requests import HTTPResponse
from artemis.module_base import ArtemisBase
from artemis.modules.data.parameters import URL_PARAMS
from artemis.modules.data.static_extensions import STATIC_EXTENSIONS
from artemis.modules.data.xss_scanner_data import XSS_INDICATORS, XSS_PAYLOADS
from artemis.task_utils import get_target_url


class XSSFindings(Enum):
    """XSS vulnerability finding types."""

    XSS_VULNERABILITY = "xss_vulnerability"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.HIGH)
class XSSScanner(ArtemisBase):
    """
    Module for detecting Cross-Site Scripting (XSS) vulnerabilities.

    This scanner uses advanced payloads that bypass common input sanitization
    and XSS protection mechanisms including:
    - HTML entity encoding evasion
    - URL encoding and double encoding
    - Unicode evasion
    - Filter bypass techniques
    - WAF bypass payloads
    - Polyglot and mutation XSS
    """

    num_retries = Config.Miscellaneous.SLOW_MODULE_NUM_RETRIES
    identity = "xss_scanner"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _strip_query_string(self, url: str) -> str:
        """Remove query string from URL."""
        url_parsed = urlparse(url)
        return urlunparse(url_parsed._replace(query="", fragment=""))

    def create_url_with_batch_payload(self, url: str, param_batch: List[str], payload: str) -> str:
        """Create URL with payload injected into multiple parameters."""
        assignments = {key: payload for key in param_batch}
        concatenation = "&" if self.is_url_with_parameters(url) else "?"
        return f"{url}{concatenation}" + "&".join(
            [f"{key}={urllib.parse.quote(value)}" for key, value in assignments.items()]
        )

    def is_url_with_parameters(self, url: str) -> bool:
        """Check if URL already has query parameters."""
        return bool(re.search(r"/?/*=", url))

    def contains_xss_indicator(
        self, original_response: HTTPResponse, response: HTTPResponse, payload: str
    ) -> Optional[str]:
        """
        Check if the response contains indicators of XSS vulnerability.

        Args:
            original_response: Response without payload injection
            response: Response with payload injection
            payload: The XSS payload that was injected

        Returns:
            Description of matched indicator or None
        """
        response_content = response.content.lower()
        original_content = original_response.content.lower()

        # Check if payload is reflected in response
        payload_lower = payload.lower()
        # Check various encodings of the payload
        payload_variations = [
            payload_lower,
            html.unescape(payload_lower),
            urllib.parse.unquote(payload_lower),
            urllib.parse.unquote(urllib.parse.unquote(payload_lower)),  # Double decode
        ]

        for variation in payload_variations:
            if variation in response_content and variation not in original_content:
                self.log.debug(f"Payload reflected in response: {variation}")
                return f"Payload reflected in response: {payload}"

        # Check for XSS indicators in new content
        for indicator in XSS_INDICATORS:
            indicator_lower = indicator.lower()
            # Check if indicator appears in response but not in original
            if indicator_lower in response_content and indicator_lower not in original_content:
                self.log.debug(f"XSS indicator detected: {indicator}")
                return f"XSS indicator detected: {indicator}"

        # Check if dangerous HTML/JavaScript patterns are present
        dangerous_patterns = [
            r"<script[^>]*>.*?alert.*?</script>",
            r"<img[^>]*onerror\s*=",
            r"<svg[^>]*onload\s*=",
            r"javascript:\s*alert",
            r"on\w+\s*=\s*alert",
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, response_content, re.IGNORECASE | re.DOTALL):
                if not re.search(pattern, original_content, re.IGNORECASE | re.DOTALL):
                    self.log.debug(f"Dangerous pattern matched: {pattern}")
                    return "Dangerous XSS pattern detected"

        return None

    def scan(self, urls: List[str], task: Task) -> List[Dict[str, Any]]:
        """
        Scan URLs for XSS vulnerabilities.

        Args:
            urls: List of URLs to scan
            task: Current Karton task

        Returns:
            List of vulnerability findings
        """
        messages: List[Dict[str, Any]] = []

        for current_url in urls:
            try:
                original_response = self.http_get(current_url)
            except Exception as e:
                self.log.debug(f"Failed to fetch {current_url}: {e}")
                continue

            parameters = get_injectable_parameters(current_url)
            self.log.info("Obtained parameters: %s for url %s", parameters, current_url)

            # Use subset of payloads to avoid excessive testing
            # Prioritize advanced evasion payloads over basic ones
            payload_subset = (
                XSS_PAYLOADS[: Config.Miscellaneous.MAX_XSS_PAYLOADS_TO_TEST]
                if hasattr(Config.Miscellaneous, "MAX_XSS_PAYLOADS_TO_TEST")
                else XSS_PAYLOADS[:50]
            )

            for payload in payload_subset:
                param_batch = []
                for i, param in enumerate(parameters + URL_PARAMS):
                    param_batch.append(param)
                    url_with_payload = self.create_url_with_batch_payload(current_url, param_batch, payload)

                    # Break down params into chunks to avoid overly long URLs
                    if len(url_with_payload) >= 1600 or i == len(parameters + URL_PARAMS) - 1:
                        try:
                            response = self.http_get(url_with_payload)

                            if indicator := self.contains_xss_indicator(original_response, response, payload):
                                messages.append(
                                    {
                                        "url": url_with_payload,
                                        "payload": payload,
                                        "parameters": param_batch.copy(),
                                        "matched_indicator": indicator,
                                        "statement": f"Potential XSS vulnerability detected at {current_url} with payload: {payload[:100]}",
                                        "code": XSSFindings.XSS_VULNERABILITY.value,
                                    }
                                )
                                # Stop testing this URL if we found a vulnerability
                                if hasattr(Config.Modules, "XSSScanner") and hasattr(
                                    Config.Modules.XSSScanner, "XSS_STOP_ON_FIRST_MATCH"
                                ):
                                    if Config.Modules.XSSScanner.XSS_STOP_ON_FIRST_MATCH:
                                        return messages
                                # Otherwise continue to next URL
                                break
                        except Exception as e:
                            self.log.debug(f"Error testing payload on {url_with_payload}: {e}")

                        param_batch = []

                    # If we found a vulnerability for this payload, move to next URL
                    if messages and messages[-1]["url"].startswith(current_url):
                        break

        return messages

    def run(self, current_task: Task) -> None:
        """
        Run the XSS scanner module.

        Args:
            current_task: Current Karton task to process
        """
        if self.check_connection_to_base_url_and_save_error(current_task):
            url = get_target_url(current_task)

            links = get_links_and_resources_on_same_domain(url)
            links.append(url)
            links = list(set(links) | set([self._strip_query_string(link) for link in links]))

            # Filter out static resources and fragments
            links = [
                link.split("#")[0]
                for link in links
                if not any(link.split("?")[0].lower().endswith(extension) for extension in STATIC_EXTENSIONS)
            ]

            random.shuffle(links)

            messages = self.scan(urls=links[: Config.Miscellaneous.MAX_URLS_TO_SCAN], task=current_task)

            if messages:
                status = TaskStatus.INTERESTING
                status_reason = ", ".join([m["statement"] for m in messages])
            else:
                status = TaskStatus.OK
                status_reason = None

            data = {"result": messages, "statements": {e.value: e.name for e in XSSFindings}}

            self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=data)


if __name__ == "__main__":
    XSSScanner().loop()
