import json
import re
import uuid
from enum import Enum
from typing import Any, Callable, TypeVar

import more_itertools
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.crawling import collect_parameters, get_links_to_scan, strip_query_string
from artemis.http_requests import HTTPResponse
from artemis.module_base import ArtemisBase
from artemis.modules.base.injection_helpers import (
    build_result_data,
    create_status_reason,
    responses_differ,
)
from artemis.nosql_injection_data import (
    BLIND_FALSE_OPERATOR,
    BLIND_TRUE_OPERATOR,
    BRACKET_OPERATOR_PAYLOADS,
    JSON_OPERATOR_PAYLOADS,
    NOSQL_ERROR_MESSAGES,
    PARAMS_PER_BATCH,
)
from artemis.task_utils import get_target_url

JSON_HEADERS = {"Content-Type": "application/json"}

# A random value no record holds ("$ne" then matches every record, "$eq" none), kept to 8 hex chars
# so that a full batch of bracket parameters stays under the URL-length limit.
UNLIKELY_VALUE = uuid.uuid4().hex[:8]

T = TypeVar("T")


class Statements(Enum):
    nosql_injection = "nosql_injection"
    nosql_injection_json_body = "nosql_injection_json_body"
    nosql_injection_blind = "nosql_injection_blind"


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.HIGH)
class NoSqlInjectionDetector(ArtemisBase):
    """
    Module for detecting MongoDB-style NoSQL injection vulnerabilities.
    """

    num_retries = Config.Miscellaneous.SLOW_MODULE_NUM_RETRIES
    identity = "nosql_injection_detector"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    @staticmethod
    def _baseline_operator(operator: str) -> str:
        # Removing the leading "$" yields a key the query engine reads as a literal subdocument
        # field rather than an operator, so the baseline request differs from the payload request
        # only in whether an operator is present.
        return operator.removeprefix("$")

    @staticmethod
    def _build_bracket_url(url: str, params: list[str], operator: str, value: str) -> str:
        # The brackets and "$" are sent literally so the target's query parser reads them as a nested
        # operator object; percent-encoding them would decode to the same thing before parsing.
        base = strip_query_string(url)
        query = "&".join(f"{name}[{operator}]={value}" for name in params)
        return f"{base}?{query}"

    @staticmethod
    def _build_json_body(params: list[str], operator: str, value: Any) -> str:
        return json.dumps({name: {operator: value} for name in params})

    def _contains_error(self, url: str, response: HTTPResponse | None) -> str | None:
        if response is None:
            return None

        for message in NOSQL_ERROR_MESSAGES:
            if re.search(message, response.content):
                self.log.debug("Matched NoSQL error: %s on %s", message, url)
                return message
        return None

    def _probe_get(self, url: str, params: list[str], operator: str, value: str) -> tuple[str | None, bool]:
        payload_url = self._build_bracket_url(url, params, operator, value)
        baseline_url = self._build_bracket_url(url, params, self._baseline_operator(operator), value)

        response_payload = self.forgiving_http_get(payload_url)
        response_baseline = self.forgiving_http_get(baseline_url)
        if response_payload is None or response_baseline is None:
            return None, False

        error = self._contains_error(payload_url, response_payload)
        if error and not self._contains_error(baseline_url, response_baseline):
            return error, True
        return None, True

    def _probe_post(self, url: str, params: list[str], operator: str, value: Any) -> tuple[str | None, bool]:
        base = strip_query_string(url)
        payload_body = self._build_json_body(params, operator, value)
        baseline_body = self._build_json_body(params, self._baseline_operator(operator), value)

        response_payload = self.forgiving_http_post(base, data=payload_body, headers=JSON_HEADERS)
        response_baseline = self.forgiving_http_post(base, data=baseline_body, headers=JSON_HEADERS)
        if response_payload is None or response_baseline is None:
            return None, False

        error = self._contains_error(base, response_payload)
        if error and not self._contains_error(base, response_baseline):
            return error, True
        return None, True

    def _has_dynamic_content(self, url: str) -> bool:
        # Two identical requests that already differ mean the endpoint is non-deterministic (timestamps,
        # tokens), so the blind differential below would flag it on every run. Skip those.
        return responses_differ(self.forgiving_http_get(url), self.forgiving_http_get(url))

    def _probe_boolean_get(self, url: str, params: list[str]) -> tuple[dict[str, str] | None, bool]:
        # Blind probe: "$ne" matches (almost) every record while "$eq" matches none, so a difference
        # between the two responses proves the operator reached the query even when no error leaks.
        true_url = self._build_bracket_url(url, params, BLIND_TRUE_OPERATOR, UNLIKELY_VALUE)
        false_url = self._build_bracket_url(url, params, BLIND_FALSE_OPERATOR, UNLIKELY_VALUE)

        response_true = self.forgiving_http_get(true_url)
        response_false = self.forgiving_http_get(false_url)
        if response_true is None or response_false is None:
            return None, False

        if responses_differ(response_true, response_false):
            return {"true": true_url, "false": false_url}, True
        return None, True

    def _probe_boolean_post(self, url: str, params: list[str]) -> tuple[dict[str, str] | None, bool]:
        base = strip_query_string(url)
        true_body = self._build_json_body(params, BLIND_TRUE_OPERATOR, UNLIKELY_VALUE)
        false_body = self._build_json_body(params, BLIND_FALSE_OPERATOR, UNLIKELY_VALUE)

        response_true = self.forgiving_http_post(base, data=true_body, headers=JSON_HEADERS)
        response_false = self.forgiving_http_post(base, data=false_body, headers=JSON_HEADERS)
        if response_true is None or response_false is None:
            return None, False

        if responses_differ(response_true, response_false):
            return {"true": true_body, "false": false_body}, True
        return None, True

    def _confirm(self, probe: Callable[..., tuple[T | None, bool]], *args: Any) -> tuple[T | None, bool]:
        """Re-runs a probe and confirms it only when every run reproduces the match, returning as soon
        as one run disagrees. The second value reports whether any run completed both its requests, so
        the caller can tell a clean result from one where the target could not be reached."""
        any_completed = False
        confirmed: T | None = None
        for _ in range(max(1, Config.Modules.NoSqlInjectionDetector.NOSQL_INJECTION_NUM_CONFIRMATIONS)):
            matched, completed = probe(*args)
            if completed:
                any_completed = True
            if not completed or matched is None:
                return None, any_completed
            confirmed = matched
        return confirmed, any_completed

    def minimize_parameters(
        self, url: str, params: list[str], probe: Callable[..., tuple[Any, bool]], *probe_args: Any
    ) -> list[str]:
        """Finds the minimal set of parameters that still triggers the match on their own, capped at
        ``NOSQL_INJECTION_MINIMAL_PARAMS_MAX_LEN``. Falls back to the full batch when no single
        parameter reproduces it. Works for any probe (error-based or blind) via ``probe_args``."""
        minimal: list[str] = []
        for param in params:
            matched, _ = probe(url, [param], *probe_args)
            if matched:
                minimal.append(param)
            if len(minimal) >= Config.Modules.NoSqlInjectionDetector.NOSQL_INJECTION_MINIMAL_PARAMS_MAX_LEN:
                break

        if minimal:
            self.log.info("NoSQL injection parameter minimization: %s -> %s", params, minimal)
            return minimal
        return params

    def scan(self, urls: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
        self.log.info("Scanning URLs: %s", urls)
        message: list[dict[str, Any]] = []
        untestable_urls: list[str] = []
        stop_on_first_match = Config.Modules.NoSqlInjectionDetector.NOSQL_INJECTION_STOP_ON_FIRST_MATCH

        for current_url in urls:
            all_params = collect_parameters(current_url)
            blind_enabled = not self._has_dynamic_content(current_url)

            url_completed = False
            for param_batch in more_itertools.batched(all_params, PARAMS_PER_BATCH):
                batch = list(param_batch)

                for operator, value in BRACKET_OPERATOR_PAYLOADS:
                    matched, completed = self._confirm(self._probe_get, current_url, batch, operator, value)
                    url_completed = url_completed or completed
                    if matched:
                        minimal = self.minimize_parameters(current_url, batch, self._probe_get, operator, value)
                        message.append(
                            {
                                "url": self._build_bracket_url(current_url, minimal, operator, value),
                                "method": "GET",
                                "parameters": minimal,
                                "payload": f"[{operator}]={value}",
                                "matched_error": matched,
                                "statement": "It appears that this URL is vulnerable to NoSQL injection",
                                "code": Statements.nosql_injection.value,
                            }
                        )
                        if stop_on_first_match:
                            return message, untestable_urls

                for operator, value in JSON_OPERATOR_PAYLOADS:
                    matched, completed = self._confirm(self._probe_post, current_url, batch, operator, value)
                    url_completed = url_completed or completed
                    if matched:
                        minimal = self.minimize_parameters(current_url, batch, self._probe_post, operator, value)
                        message.append(
                            {
                                "url": strip_query_string(current_url),
                                "method": "POST",
                                "parameters": minimal,
                                "payload": self._build_json_body(minimal, operator, value),
                                "matched_error": matched,
                                "statement": "It appears that this URL is vulnerable to NoSQL injection through a JSON body",
                                "code": Statements.nosql_injection_json_body.value,
                            }
                        )
                        if stop_on_first_match:
                            return message, untestable_urls

                if not blind_enabled:
                    continue

                blind_matched, completed = self._confirm(self._probe_boolean_get, current_url, batch)
                url_completed = url_completed or completed
                if blind_matched:
                    minimal = self.minimize_parameters(current_url, batch, self._probe_boolean_get)
                    message.append(
                        {
                            "url": self._build_bracket_url(current_url, minimal, BLIND_TRUE_OPERATOR, UNLIKELY_VALUE),
                            "method": "GET",
                            "parameters": minimal,
                            "payload": f"[{BLIND_TRUE_OPERATOR}]={UNLIKELY_VALUE}",
                            "baseline": f"[{BLIND_FALSE_OPERATOR}]={UNLIKELY_VALUE}",
                            "statement": "It appears that this URL is vulnerable to blind NoSQL injection",
                            "code": Statements.nosql_injection_blind.value,
                        }
                    )
                    if stop_on_first_match:
                        return message, untestable_urls

                blind_matched, completed = self._confirm(self._probe_boolean_post, current_url, batch)
                url_completed = url_completed or completed
                if blind_matched:
                    minimal = self.minimize_parameters(current_url, batch, self._probe_boolean_post)
                    message.append(
                        {
                            "url": strip_query_string(current_url),
                            "method": "POST",
                            "parameters": minimal,
                            "payload": self._build_json_body(minimal, BLIND_TRUE_OPERATOR, UNLIKELY_VALUE),
                            "baseline": self._build_json_body(minimal, BLIND_FALSE_OPERATOR, UNLIKELY_VALUE),
                            "statement": "It appears that this URL is vulnerable to blind NoSQL injection through a JSON body",
                            "code": Statements.nosql_injection_blind.value,
                        }
                    )
                    if stop_on_first_match:
                        return message, untestable_urls

            if not url_completed:
                untestable_urls.append(current_url)

        return message, untestable_urls

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)

        scanned = get_links_to_scan(url)

        message, untestable_urls = self.scan(urls=scanned)

        if message:
            status = TaskStatus.INTERESTING
            status_reason = create_status_reason(message)
        elif scanned and len(untestable_urls) == len(scanned):
            # Every discovered URL failed its baseline request, so nothing could actually be tested.
            # A failed check must be saved as an error, not as a clean OK with no findings.
            status = TaskStatus.ERROR
            status_reason = "Could not test any discovered URL: " + ", ".join(untestable_urls)
        else:
            status = TaskStatus.OK
            status_reason = None

        data = build_result_data(
            message,
            {
                "nosql_injection": Statements.nosql_injection.value,
                "nosql_injection_json_body": Statements.nosql_injection_json_body.value,
                "nosql_injection_blind": Statements.nosql_injection_blind.value,
            },
            untestable_urls=untestable_urls,
        )

        self.save_task_result(task=current_task, status=status, status_reason=status_reason, data=data)


if __name__ == "__main__":
    NoSqlInjectionDetector.parallel_loop()
