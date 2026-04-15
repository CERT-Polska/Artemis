from enum import Enum
from typing import Any, Dict, List, Optional

from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskType
from artemis.config import Config
from artemis.crawling import get_injectable_parameters
from artemis.http_requests import HTTPResponse
from artemis.injection_utils import (
    collect_urls_to_scan,
    create_url_with_batch_payload,
    process_and_save_scan_results,
)
from artemis.module_base import ArtemisBase
from artemis.modules.data.lfi_detector.lfi_detector_data import (
    LFI_PAYLOADS,
    RCE_PAYLOADS,
)
from artemis.modules.data.parameters import URL_PARAMS
from artemis.task_utils import get_target_url


class LFIFindings(Enum):
    LFI_VULNERABILITY = "lfi_vulnerability"
    RCE_VULNERABILITY = "rce_vulnerability"


vulnerability_to_message = {
    LFIFindings.LFI_VULNERABILITY: "It appears that this URL is vulnerable to LFI:",
    LFIFindings.RCE_VULNERABILITY: "It appears that this URL is vulnerable to RCE:",
}


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.HIGH)
class LFIDetector(ArtemisBase):
    """
    Module for detecting Local File Inclusion (LFI) vulnerabilities.
    """

    num_retries = Config.Miscellaneous.SLOW_MODULE_NUM_RETRIES
    identity = "lfi_detector"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def contains_lfi_indicator(self, original_response: HTTPResponse, response: HTTPResponse) -> Optional[str]:
        """Check if the response contains indicators of LFI."""
        indicators = [
            ("root:x:", "/etc/passwd"),
            ("Windows Registry Editor", "Windows .ini file"),
        ]
        for indicator, description in indicators:
            if indicator in response.content and indicator not in original_response.content:
                self.log.debug(f"Matched LFI indicator: {description}")
                return description
        return None

    def minimize_parameters(
        self, url: str, params: List[str], payload: str, original_response: HTTPResponse
    ) -> List[str]:
        """
        Try to find the minimal set of parameters that still triggers LFI. Currently minimizes to single parameters only.
        Falls back to original params if none work individually.
        """
        minimal_params: List[str] = []

        for param in params:
            test_url = create_url_with_batch_payload(url, [param], payload)
            response = self.http_get(test_url)

            if self.contains_lfi_indicator(original_response, response):
                minimal_params.append(param)

        if minimal_params:
            capped_minimal_params = minimal_params[: Config.Modules.LFIDetector.LFI_MINIMAL_PARAMS_MAX_LEN]
            self.log.info(
                "LFI parameter minimization: %s -> %s",
                params,
                capped_minimal_params,
            )
            return capped_minimal_params

        # fallback if no single param triggers LFI
        return params

    def scan(self, urls: List[str], task: Task) -> List[Dict[str, Any]]:
        """Scan URLs for LFI vulnerabilities."""
        messages: List[Dict[str, Any]] = []

        for current_url in urls:
            original_response = self.http_get(current_url)

            parameters = get_injectable_parameters(current_url)
            self.log.info("Obtained parameters: %s for url %s", parameters, current_url)

            for vulnerability, payloads in [
                (LFIFindings.LFI_VULNERABILITY, LFI_PAYLOADS),
                (LFIFindings.RCE_VULNERABILITY, RCE_PAYLOADS),
            ]:
                for payload in payloads:
                    param_batch = []
                    total_params = parameters + URL_PARAMS
                    for i, param in enumerate(total_params):
                        param_batch.append(param)
                        url_with_payload = create_url_with_batch_payload(current_url, param_batch, payload)

                        # The idea of that check is to break down params into chunks that lead to a given maximum URL
                        # length (as longer URLs may be unsupported by the servers).
                        #
                        # We can't have constant chunk size as the payloads have varied length.
                        if len(url_with_payload) >= 1600 or i == len(total_params) - 1:
                            response = self.http_get(url_with_payload)

                            if indicator := self.contains_lfi_indicator(original_response, response):

                                minimal_params = self.minimize_parameters(
                                    current_url,
                                    param_batch,
                                    payload,
                                    original_response,
                                )

                                minimal_url = create_url_with_batch_payload(
                                    current_url,
                                    minimal_params,
                                    payload,
                                )

                                messages.append(
                                    {
                                        "url": minimal_url,
                                        "headers": {},
                                        "matched_indicator": indicator,
                                        "statement": vulnerability_to_message[vulnerability] + " " + minimal_url,
                                        "code": vulnerability.value,
                                    }
                                )
                                if Config.Modules.LFIDetector.LFI_STOP_ON_FIRST_MATCH:
                                    return messages
                            param_batch = []

        return messages

    def run(self, current_task: Task) -> None:
        """Run the LFI detection module."""
        if self.check_connection_to_base_url_and_save_error(current_task):
            url = get_target_url(current_task)

            links = collect_urls_to_scan(url)

            messages = self.scan(urls=links, task=current_task)

            process_and_save_scan_results(messages, LFIFindings, current_task, self.db)


if __name__ == "__main__":
    LFIDetector.parallel_loop()
