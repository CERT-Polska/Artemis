import random
import re
import html
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlencode, urlparse, urlunparse

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
from artemis.modules.data.xss_scanner.xss_scanner_data import (
    BASIC_XSS_PAYLOADS,
    ENCODING_BYPASS_PAYLOADS,
    FILTER_EVASION_PAYLOADS,
    WAF_BYPASS_PAYLOADS,
    CONTEXT_AWARE_PAYLOADS,
    FRAMEWORK_BYPASS_PAYLOADS,
)
from artemis.task_utils import get_target_url


class XSSFindings(Enum):
    """Enum for different types of XSS vulnerabilities."""
    REFLECTED_XSS = "reflected_xss"
    REFLECTED_XSS_ENCODING_BYPASS = "reflected_xss_encoding_bypass"
    REFLECTED_XSS_FILTER_EVASION = "reflected_xss_filter_evasion"
    REFLECTED_XSS_WAF_BYPASS = "reflected_xss_waf_bypass"
    REFLECTED_XSS_CONTEXT_AWARE = "reflected_xss_context_aware"
    REFLECTED_XSS_FRAMEWORK_BYPASS = "reflected_xss_framework_bypass"
    HEADER_XSS = "header_xss"


vulnerability_to_message = {
    XSSFindings.REFLECTED_XSS: "Basic reflected XSS vulnerability detected",
    XSSFindings.REFLECTED_XSS_ENCODING_BYPASS: "Reflected XSS via encoding bypass detected",
    XSSFindings.REFLECTED_XSS_FILTER_EVASION: "Reflected XSS via filter evasion detected",
    XSSFindings.REFLECTED_XSS_WAF_BYPASS: "Reflected XSS via WAF bypass detected",
    XSSFindings.REFLECTED_XSS_CONTEXT_AWARE: "Reflected XSS via context-aware injection detected",
    XSSFindings.REFLECTED_XSS_FRAMEWORK_BYPASS: "Reflected XSS via framework-specific bypass detected",
    XSSFindings.HEADER_XSS: "XSS vulnerability in HTTP headers detected",
}


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.HIGH)
class XSSScanner(ArtemisBase):
    """
    Module for detecting Cross-Site Scripting (XSS) vulnerabilities using unconventional payloads
    designed to bypass modern input sanitation and XSS protection mechanisms.
    """

    num_retries = Config.Miscellaneous.SLOW_MODULE_NUM_RETRIES
    identity = "xss_scanner"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    # XSS-specific configurations (with fallback to config if available)
    XSS_STOP_ON_FIRST_MATCH = getattr(
        getattr(Config.Modules, "XSSScanner", None),
        "XSS_STOP_ON_FIRST_MATCH",
        False
    )
    XSS_MAX_PAYLOADS_PER_CATEGORY = getattr(
        getattr(Config.Modules, "XSSScanner", None),
        "XSS_MAX_PAYLOADS_PER_CATEGORY",
        50  # Limit payloads per category to avoid excessive testing
    )
    XSS_ENABLE_HEADER_TESTING = getattr(
        getattr(Config.Modules, "XSSScanner", None),
        "XSS_ENABLE_HEADER_TESTING",
        True
    )

    @staticmethod
    def _strip_query_string(url: str) -> str:
        """Remove query string and fragment from URL."""
        url_parsed = urlparse(url)
        return urlunparse(url_parsed._replace(query="", fragment=""))

    def create_url_with_batch_payload(self, url: str, param_batch: List[str], payload: str) -> str:
        """Create URL with payload injected into specified parameters."""
        assignments = {key: payload for key in param_batch}
        concatenation = "&" if self.is_url_with_parameters(url) else "?"
        return f"{url}{concatenation}" + "&".join([f"{key}={value}" for key, value in assignments.items()])

    @staticmethod
    def is_url_with_parameters(url: str) -> bool:
        """Check if URL already contains parameters."""
        return bool(re.search(r"/?/*=", url))

    @staticmethod
    def change_url_params(url: str, payload: str, param_batch: List[str]) -> str:
        """Modify existing URL parameters with payload."""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        params = list(query_params.keys())
        new_query_params = {}

        # Set all existing parameters to payload
        for param in params:
            new_query_params[param] = [payload]

        # Add batch parameters
        for param in param_batch:
            new_query_params[param] = [payload]

        new_query_string = urlencode(new_query_params, doseq=True)
        new_url = urlunparse(
            (
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query_string,
                parsed_url.fragment,
            )
        )
        return unquote(new_url)

    def detect_xss_in_response(
        self,
        payload: str,
        response: Optional[HTTPResponse],
        original_response: Optional[HTTPResponse] = None
    ) -> Tuple[bool, str]:
        """
        Detect if XSS payload is reflected in the response.
        
        Returns:
            Tuple[bool, str]: (is_vulnerable, detection_context)
        """
        if response is None or not response.content:
            return False, ""

        content = response.content.lower()
        payload_lower = payload.lower()

        # Check for direct reflection (unencoded)
        if payload_lower in content:
            # Determine injection context
            context = self._identify_injection_context(payload, response.content)
            return True, f"Direct reflection in {context} context"

        # Check for HTML-encoded reflection
        html_encoded = html.escape(payload).lower()
        if html_encoded in content and html_encoded != payload_lower:
            return True, "HTML-encoded reflection (possible sanitization attempt)"

        # Check for URL-encoded reflection
        from urllib.parse import quote
        url_encoded = quote(payload).lower()
        if url_encoded in content:
            return True, "URL-encoded reflection"

        # Check for partial reflection (tag-only, without payload)
        # This can indicate filter bypass opportunities
        tag_patterns = [
            r"<script[^>]*>",
            r"<img[^>]*>",
            r"<svg[^>]*>",
            r"onerror\s*=",
            r"onload\s*=",
        ]
        for pattern in tag_patterns:
            if re.search(pattern, content) and original_response:
                if not re.search(pattern, original_response.content.lower()):
                    return True, "Partial reflection - injected tag detected"

        # Check for JavaScript execution indicators (for advanced payloads)
        js_execution_indicators = [
            "alert(",
            "prompt(",
            "confirm(",
            "console.log(",
            "document.cookie",
        ]
        
        if any(indicator in content for indicator in js_execution_indicators):
            if original_response and not any(
                indicator in original_response.content.lower()
                for indicator in js_execution_indicators
            ):
                return True, "JavaScript execution context detected"

        return False, ""

    def _identify_injection_context(self, payload: str, response_content: str) -> str:
        """
        Identify where the payload was injected (HTML, attribute, script, etc.).
        """
        # Find payload location in response
        payload_lower = payload.lower()
        content_lower = response_content.lower()
        
        payload_index = content_lower.find(payload_lower)
        if payload_index == -1:
            return "unknown"

        # Analyze surrounding context (100 chars before and after)
        start = max(0, payload_index - 100)
        end = min(len(response_content), payload_index + len(payload) + 100)
        context_snippet = response_content[start:end]

        # Check contexts in order of specificity
        if re.search(r'<script[^>]*>.*?' + re.escape(payload), context_snippet, re.IGNORECASE | re.DOTALL):
            return "script tag"
        
        if re.search(r'<style[^>]*>.*?' + re.escape(payload), context_snippet, re.IGNORECASE | re.DOTALL):
            return "style tag"
        
        if re.search(r'(?:on\w+)\s*=\s*["\']?' + re.escape(payload), context_snippet, re.IGNORECASE):
            return "event handler attribute"
        
        if re.search(r'(?:href|src|data|action)\s*=\s*["\']?' + re.escape(payload), context_snippet, re.IGNORECASE):
            return "URL attribute"
        
        if re.search(r'<[^>]+\s+[^>]*' + re.escape(payload), context_snippet, re.IGNORECASE):
            return "HTML attribute"
        
        if re.search(r'<[^>]*>', context_snippet):
            return "HTML body"
        
        return "text content"

    @staticmethod
    def create_xss_headers(payload: str) -> Dict[str, str]:
        """Create headers with XSS payloads for header injection testing."""
        return {
            "User-Agent": payload,
            "Referer": payload,
            "X-Forwarded-For": payload,
            "X-Forwarded-Host": payload,
            "X-Original-URL": payload,
            "X-Rewrite-URL": payload,
        }

    def scan(self, urls: List[str], task: Task) -> List[Dict[str, Any]]:
        """
        Scan URLs for XSS vulnerabilities using multiple payload categories.
        """
        self.log.info("Scanning %d URLs for XSS vulnerabilities", len(urls))
        messages: List[Dict[str, Any]] = []

        # Organize payloads by category with their corresponding finding type
        payload_categories = [
            (BASIC_XSS_PAYLOADS[:self.XSS_MAX_PAYLOADS_PER_CATEGORY], XSSFindings.REFLECTED_XSS, "basic"),
            (ENCODING_BYPASS_PAYLOADS[:self.XSS_MAX_PAYLOADS_PER_CATEGORY], XSSFindings.REFLECTED_XSS_ENCODING_BYPASS, "encoding_bypass"),
            (FILTER_EVASION_PAYLOADS[:self.XSS_MAX_PAYLOADS_PER_CATEGORY], XSSFindings.REFLECTED_XSS_FILTER_EVASION, "filter_evasion"),
            (WAF_BYPASS_PAYLOADS[:self.XSS_MAX_PAYLOADS_PER_CATEGORY], XSSFindings.REFLECTED_XSS_WAF_BYPASS, "waf_bypass"),
            (CONTEXT_AWARE_PAYLOADS[:self.XSS_MAX_PAYLOADS_PER_CATEGORY], XSSFindings.REFLECTED_XSS_CONTEXT_AWARE, "context_aware"),
            (FRAMEWORK_BYPASS_PAYLOADS[:self.XSS_MAX_PAYLOADS_PER_CATEGORY], XSSFindings.REFLECTED_XSS_FRAMEWORK_BYPASS, "framework_bypass"),
        ]

        for current_url in urls:
            self.log.info("Testing URL: %s", current_url)
            
            # Get original response for comparison
            original_response = self.forgiving_http_get(current_url)
            
            # Get injectable parameters
            parameters = get_injectable_parameters(current_url)
            self.log.info("Found %d injectable parameters for %s", len(parameters), current_url)

            # Test each payload category
            for payloads, finding_type, category_name in payload_categories:
                self.log.debug("Testing %s payloads (%d total)", category_name, len(payloads))
                
                for payload in payloads:
                    # Test URL parameters
                    if self.is_url_with_parameters(current_url) and parameters:
                        # Test modifying existing parameters
                        url_with_payload = self.change_url_params(
                            url=current_url,
                            payload=payload,
                            param_batch=parameters[:5]  # Limit to first 5 params
                        )
                        
                        response = self.forgiving_http_get(url_with_payload)
                        is_vulnerable, context = self.detect_xss_in_response(
                            payload, response, original_response
                        )
                        
                        if is_vulnerable:
                            messages.append({
                                "url": url_with_payload,
                                "payload": payload,
                                "category": category_name,
                                "injection_point": "url_parameters",
                                "context": context,
                                "statement": f"{vulnerability_to_message[finding_type]} - {context}",
                                "code": finding_type.value,
                            })
                            
                            if self.XSS_STOP_ON_FIRST_MATCH:
                                return messages

                    # Test adding new parameters
                    for param_batch in self._batch_parameters(parameters + URL_PARAMS, 10):
                        url_with_payload = self.create_url_with_batch_payload(
                            url=current_url,
                            param_batch=param_batch,
                            payload=payload
                        )
                        
                        response = self.forgiving_http_get(url_with_payload)
                        is_vulnerable, context = self.detect_xss_in_response(
                            payload, response, original_response
                        )
                        
                        if is_vulnerable:
                            messages.append({
                                "url": url_with_payload,
                                "payload": payload,
                                "category": category_name,
                                "injection_point": "injected_parameters",
                                "context": context,
                                "statement": f"{vulnerability_to_message[finding_type]} - {context}",
                                "code": finding_type.value,
                            })
                            
                            if self.XSS_STOP_ON_FIRST_MATCH:
                                return messages

            # Test HTTP headers for XSS (if enabled)
            if self.XSS_ENABLE_HEADER_TESTING:
                self.log.debug("Testing HTTP headers for XSS")
                
                # Test with basic payloads only for headers to avoid excessive requests
                for payload in BASIC_XSS_PAYLOADS[:10]:
                    headers = self.create_xss_headers(payload)
                    response = self.forgiving_http_get(current_url, headers=headers)
                    
                    is_vulnerable, context = self.detect_xss_in_response(
                        payload, response, original_response
                    )
                    
                    if is_vulnerable:
                        messages.append({
                            "url": current_url,
                            "payload": payload,
                            "category": "header_injection",
                            "injection_point": "http_headers",
                            "context": context,
                            "headers": headers,
                            "statement": f"{vulnerability_to_message[XSSFindings.HEADER_XSS]} - {context}",
                            "code": XSSFindings.HEADER_XSS.value,
                        })
                        
                        if self.XSS_STOP_ON_FIRST_MATCH:
                            return messages

        return messages

    @staticmethod
    def _batch_parameters(params: List[str], batch_size: int) -> List[List[str]]:
        """Split parameters into batches."""
        return [params[i:i + batch_size] for i in range(0, len(params), batch_size)]

    def run(self, current_task: Task) -> None:
        """Run the XSS scanner module."""
        url = get_target_url(current_task)
        
        # Get links on same domain
        links = get_links_and_resources_on_same_domain(url)
        links.append(url)
        links = list(set(links) | set([self._strip_query_string(link) for link in links]))

        # Filter out static resources
        links = [
            link.split("#")[0]
            for link in links
            if not any(link.split("?")[0].lower().endswith(extension) for extension in STATIC_EXTENSIONS)
        ]

        # Randomize to spread load
        random.shuffle(links)

        # Scan limited number of URLs
        messages = self.scan(urls=links[:Config.Miscellaneous.MAX_URLS_TO_SCAN], task=current_task)

        # Prepare results
        if messages:
            status = TaskStatus.INTERESTING
            # Create concise status reason with unique findings
            unique_findings = set()
            for msg in messages:
                unique_findings.add(f"{msg['code']} at {msg.get('injection_point', 'unknown')}")
            status_reason = f"Found {len(messages)} XSS vulnerabilities: " + ", ".join(list(unique_findings)[:3])
        else:
            status = TaskStatus.OK
            status_reason = None

        data = {
            "result": messages,
            "statements": {e.value: e.name for e in XSSFindings},
            "summary": {
                "total_findings": len(messages),
                "urls_tested": len(links[:Config.Miscellaneous.MAX_URLS_TO_SCAN]),
                "categories_found": list(set(msg["category"] for msg in messages)),
            }
        }

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=data)


if __name__ == "__main__":
    XSSScanner().loop()
