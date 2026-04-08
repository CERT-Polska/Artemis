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
from artemis.orm_injection_data import (
    COMMON_PARAM_NAMES,
    ORM_LOOKUP_SUFFIXES,
    SENSITIVE_FIELD_PROBES,
)
from artemis.task_utils import get_target_url

UNLIKELY_VALUE = "ZZZXQQIMPOSSIBLE99"


class Statements(Enum):
    orm_injection = "orm_injection"
    orm_sensitive_field_access = "orm_sensitive_field_access"


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.HIGH)
class OrmInjectionDetector(ArtemisBase):
    """
    Module for detecting ORM injection vulnerabilities.

    Detection strategies are split into separate methods per ORM style so that
    new styles (e.g. SQLAlchemy, Sequelize) can be added independently:
      - _test_django_style_lookups: Django __lookup suffix injection
      - _test_django_sensitive_field_probes: Django sensitive field enumeration
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
        if response_a is None or response_b is None:
            return False

        # Skip server errors — a 5xx is noise (e.g. the server crashing on an unexpected param),
        # not evidence of ORM processing. 4xx responses are kept as some apps return e.g. 404
        # for "no matching records".
        status_a = response_a.status_code
        status_b = response_b.status_code
        if status_a >= 500 or status_b >= 500:
            return False

        text_a = self._get_response_text(response_a)
        text_b = self._get_response_text(response_b)

        return text_a != text_b

    def _build_url_with_params(self, base_url: str, params: Dict[str, str]) -> str:
        parsed = urlparse(base_url)
        existing_params = parse_qs(parsed.query)
        merged = {k: v[0] if isinstance(v, list) else v for k, v in existing_params.items()}
        merged.update(params)
        new_query = urlencode(merged)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    def _has_dynamic_content(self, url: str) -> bool:
        """Sends the same request twice to check if the endpoint returns non-deterministic
        content (e.g. timestamps, random tokens). If it does, differential analysis would
        produce false positives."""
        response_a = self.forgiving_http_get(url)
        response_b = self.forgiving_http_get(url)
        return self._responses_differ(response_a, response_b)

    def _test_lookup_suffix(self, original_url: str, param_name: str, suffix: str, likely_value: str) -> bool:
        # Sends two requests: one with a value likely to match records and one with a value
        # unlikely to match. If the responses differ, the ORM is processing the suffix.
        param_with_suffix = f"{param_name}{suffix}"

        # Preserve sibling query params, replacing only the param under test
        parsed = urlparse(original_url)
        siblings = {k: v[0] for k, v in parse_qs(parsed.query).items() if k != param_name}
        base = self._strip_query_string(original_url)

        # Skip endpoints with non-deterministic content to avoid false positives
        if self._has_dynamic_content(original_url):
            return False

        url_likely = self._build_url_with_params(base, {**siblings, param_with_suffix: likely_value})
        url_unlikely = self._build_url_with_params(base, {**siblings, param_with_suffix: UNLIKELY_VALUE})

        response_likely = self.forgiving_http_get(url_likely)
        response_unlikely = self.forgiving_http_get(url_unlikely)

        return self._responses_differ(response_likely, response_unlikely)

    def _get_django_likely_value(self, suffix: str, original_value: str) -> str:
        if suffix in ("__startswith", "__istartswith"):
            return original_value[:1] if original_value else "a"
        elif suffix in ("__contains", "__icontains"):
            return original_value[:2] if len(original_value) >= 2 else original_value or "a"
        elif suffix in ("__endswith", "__iendswith"):
            return original_value[-1:] if original_value else "a"
        elif suffix in ("__gt", "__gte"):
            return "0"
        elif suffix in ("__lt", "__lte"):
            return "zzzzzzzzz"
        elif suffix in ("__exact", "__iexact"):
            return original_value
        elif suffix in ("__regex", "__iregex"):
            return ".*"
        return original_value

    def _test_django_style_lookups(
        self, current_url: str, base_url: str, query_params: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """Tests for Django-style ORM injection by appending lookup suffixes (e.g. __contains,
        __startswith) to existing query parameters and checking for differential responses."""
        results: List[Dict[str, Any]] = []

        for param_name, values in query_params.items():
            original_value = values[0] if values else ""

            for suffix in ORM_LOOKUP_SUFFIXES:
                likely_value = self._get_django_likely_value(suffix, original_value)

                if self._test_lookup_suffix(current_url, param_name, suffix, likely_value):
                    self.log.info("Matched ORM lookup: %s%s on %s", param_name, suffix, current_url)
                    results.append(
                        {
                            "url": current_url,
                            "parameter": param_name,
                            "suffix": suffix,
                            "statement": "It appears that this URL is vulnerable to ORM injection",
                            "code": Statements.orm_injection.value,
                        }
                    )
                    if Config.Modules.OrmInjectionDetector.ORM_INJECTION_STOP_ON_FIRST_MATCH:
                        return results
                    break

        return results

    def _test_django_sensitive_field_probes(self, base_url: str) -> List[Dict[str, Any]]:
        """Probes for Django-style ORM access to sensitive database fields (e.g. password, is_admin)
        by injecting field__lookup parameters even on URLs without existing query parameters."""
        results: List[Dict[str, Any]] = []

        # Skip endpoints with non-deterministic content to avoid false positives
        if self._has_dynamic_content(base_url):
            return results

        for field_name, lookup, probe_value in SENSITIVE_FIELD_PROBES:
            param_with_lookup = f"{field_name}__{lookup}"

            url_with_probe = self._build_url_with_params(base_url, {param_with_lookup: probe_value})
            url_with_unlikely = self._build_url_with_params(base_url, {param_with_lookup: UNLIKELY_VALUE})

            response_probe = self.forgiving_http_get(url_with_probe)
            response_unlikely = self.forgiving_http_get(url_with_unlikely)

            if self._responses_differ(response_probe, response_unlikely):
                self.log.info("Matched ORM sensitive field: %s on %s", param_with_lookup, base_url)
                results.append(
                    {
                        "url": base_url,
                        "parameter": param_with_lookup,
                        "suffix": f"__{lookup}",
                        "statement": "It appears that this URL allows ORM filtering on sensitive fields",
                        "code": Statements.orm_sensitive_field_access.value,
                    }
                )
                if Config.Modules.OrmInjectionDetector.ORM_INJECTION_STOP_ON_FIRST_MATCH:
                    return results
                break

        return results

    def scan(self, urls: List[str], task: Task) -> List[Dict[str, Any]]:
        self.log.info("Scanning URLs: %s", urls)
        message: List[Dict[str, Any]] = []

        for current_url in urls:
            parsed = urlparse(current_url)
            query_params = parse_qs(parsed.query)
            base_url = self._strip_query_string(current_url)

            # Use existing query params if present, otherwise probe with common param names
            if query_params:
                params_to_test = query_params
            else:
                params_to_test = {name: ["test"] for name in COMMON_PARAM_NAMES}

            lookup_results = self._test_django_style_lookups(current_url, base_url, params_to_test)
            message.extend(lookup_results)
            if lookup_results and Config.Modules.OrmInjectionDetector.ORM_INJECTION_STOP_ON_FIRST_MATCH:
                return message

            field_results = self._test_django_sensitive_field_probes(base_url)
            message.extend(field_results)
            if field_results and Config.Modules.OrmInjectionDetector.ORM_INJECTION_STOP_ON_FIRST_MATCH:
                return message

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
