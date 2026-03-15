import random
import urllib
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import more_itertools
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.crawling import get_links_and_resources_on_same_domain
from artemis.http_requests import HTTPResponse
from artemis.module_base import ArtemisBase
from artemis.modules.data.static_extensions import STATIC_EXTENSIONS
from artemis.orm_injection_data import ORM_LOOKUP_SUFFIXES, SENSITIVE_FIELD_PROBES
from artemis.task_utils import get_target_url

UNLIKELY_VALUE = "ZZZXQQIMPOSSIBLE99"


class Statements(Enum):
    orm_injection = "orm_injection"
    orm_sensitive_field_access = "orm_sensitive_field_access"


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.HIGH)
class OrmInjectionDetector(ArtemisBase):
    """
    Module for detecting basic ORM injection vulnerabilities, currently focused
    on Django-style query parameter manipulation (the most common case).
    """

    num_retries = Config.Miscellaneous.SLOW_MODULE_NUM_RETRIES
    identity = "orm_injection_detector"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    @staticmethod
    def _strip_query_string(url: str) -> str:
        url_parsed = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse(url_parsed._replace(query="", fragment=""))

    @staticmethod
    def _get_response_text(response: Optional[HTTPResponse]) -> str:
        if response is None:
            return ""
        return response.content

    def _responses_differ(self, response_a: Optional[HTTPResponse], response_b: Optional[HTTPResponse]) -> bool:
        text_a = self._get_response_text(response_a)
        text_b = self._get_response_text(response_b)

        if not text_a and not text_b:
            return False

        status_a = response_a.status_code if response_a else 0
        status_b = response_b.status_code if response_b else 0
        if status_a != status_b:
            return True

        return text_a != text_b

    def _build_url_with_params(self, base_url: str, params: Dict[str, str]) -> str:
        parsed = urlparse(base_url)
        existing_params = parse_qs(parsed.query)
        merged = {k: v[0] if isinstance(v, list) else v for k, v in existing_params.items()}
        merged.update(params)
        new_query = urlencode(merged)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    def _test_lookup_suffix(self, base_url: str, param_name: str, suffix: str, likely_value: str) -> bool:
        # Sends two requests: one with a value likely to match records and one with a value
        # unlikely to match. If the responses differ, the ORM is processing the suffix.
        param_with_suffix = f"{param_name}{suffix}"

        url_likely = self._build_url_with_params(base_url, {param_with_suffix: likely_value})
        url_unlikely = self._build_url_with_params(base_url, {param_with_suffix: UNLIKELY_VALUE})

        response_likely = self.forgiving_http_get(url_likely)
        response_unlikely = self.forgiving_http_get(url_unlikely)

        if not self._responses_differ(response_likely, response_unlikely):
            return False

        # Double-check: the baseline (original URL without the suffix param) should differ
        # from at least one of the above to confirm the suffix is actually being processed
        baseline_response = self.forgiving_http_get(base_url)
        baseline_text = self._get_response_text(baseline_response)
        likely_text = self._get_response_text(response_likely)
        unlikely_text = self._get_response_text(response_unlikely)

        if baseline_text != likely_text or baseline_text != unlikely_text:
            return True

        return False

    def scan(self, urls: List[str], task: Task) -> List[Dict[str, Any]]:
        self.log.info("Scanning URLs: %s", urls)
        message: List[Dict[str, Any]] = []

        for current_url in urls:
            parsed = urlparse(current_url)
            query_params = parse_qs(parsed.query)

            base_url = self._strip_query_string(current_url)

            for param_name, values in query_params.items():
                original_value = values[0] if values else ""

                for suffix in ORM_LOOKUP_SUFFIXES:
                    if suffix in ("__startswith", "__istartswith"):
                        likely_value = original_value[:1] if original_value else "a"
                    elif suffix in ("__contains", "__icontains"):
                        likely_value = original_value[:2] if len(original_value) >= 2 else original_value or "a"
                    elif suffix in ("__endswith", "__iendswith"):
                        likely_value = original_value[-1:] if original_value else "a"
                    elif suffix in ("__gt", "__gte"):
                        likely_value = ""
                    elif suffix in ("__lt", "__lte"):
                        likely_value = "zzzzzzzzz"
                    elif suffix in ("__exact", "__iexact"):
                        likely_value = original_value
                    elif suffix in ("__regex", "__iregex"):
                        likely_value = ".*"
                    else:
                        likely_value = original_value

                    if self._test_lookup_suffix(base_url, param_name, suffix, likely_value):
                        self.log.info("Matched ORM lookup: %s%s on %s", param_name, suffix, current_url)
                        message.append(
                            {
                                "url": current_url,
                                "parameter": param_name,
                                "suffix": suffix,
                                "statement": "It appears that this URL is vulnerable to ORM injection",
                                "code": Statements.orm_injection.value,
                            }
                        )
                        if Config.Modules.OrmInjectionDetector.ORM_INJECTION_STOP_ON_FIRST_MATCH:
                            return message
                        break

            for field_name, lookup, probe_value in SENSITIVE_FIELD_PROBES:
                param_with_lookup = f"{field_name}__{lookup}"

                url_with_probe = self._build_url_with_params(base_url, {param_with_lookup: probe_value})
                url_with_unlikely = self._build_url_with_params(base_url, {param_with_lookup: UNLIKELY_VALUE})

                response_probe = self.forgiving_http_get(url_with_probe)
                response_unlikely = self.forgiving_http_get(url_with_unlikely)

                if self._responses_differ(response_probe, response_unlikely):
                    self.log.info("Matched ORM sensitive field: %s on %s", param_with_lookup, base_url)
                    message.append(
                        {
                            "url": base_url,
                            "parameter": param_with_lookup,
                            "suffix": f"__{lookup}",
                            "statement": "It appears that this URL allows ORM filtering on sensitive fields",
                            "code": Statements.orm_sensitive_field_access.value,
                        }
                    )
                    if Config.Modules.OrmInjectionDetector.ORM_INJECTION_STOP_ON_FIRST_MATCH:
                        return message
                    break

        return message

    @staticmethod
    def create_status_reason(message: Any) -> str:
        status_reason = []
        for injection_message in message:
            status_reason.append(f"{injection_message.get('url')}: {injection_message.get('statement')}")
        return ", ".join(set(status_reason))

    @staticmethod
    def create_data(message: Any) -> Dict[str, List[str] | dict[str, Any]]:
        message = list(more_itertools.unique_everseen(message))
        data = {
            "result": message,
            "statements": {
                "orm_injection": Statements.orm_injection.value,
                "orm_sensitive_field_access": Statements.orm_sensitive_field_access.value,
            },
        }
        return data

    def run(self, current_task: Task) -> None:
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

        message = self.scan(urls=links[: Config.Miscellaneous.MAX_URLS_TO_SCAN], task=current_task)

        if message:
            status = TaskStatus.INTERESTING
            status_reason = self.create_status_reason(message=message)
        else:
            status = TaskStatus.OK
            status_reason = None

        data = self.create_data(message=message)

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=data)


if __name__ == "__main__":
    OrmInjectionDetector().loop()
