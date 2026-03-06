from enum import Enum
from typing import Any, Dict, List, Optional

from karton.core import Task

from artemis import load_risk_class
from artemis.config import Config
from artemis.crawling import get_injectable_parameters
from artemis.http_requests import HTTPResponse
from artemis.modules.data.lfi_detector.lfi_detector_data import (
    LFI_PAYLOADS,
    RCE_PAYLOADS,
)
from artemis.modules.data.parameters import URL_PARAMS
from artemis.modules.injection_detector_base import InjectionDetectorBase


class LFIFindings(Enum):
    LFI_VULNERABILITY = "lfi_vulnerability"
    RCE_VULNERABILITY = "rce_vulnerability"


vulnerability_to_message = {
    LFIFindings.LFI_VULNERABILITY: "It appears that this URL is vulnerable to LFI:",
    LFIFindings.RCE_VULNERABILITY: "It appears that this URL is vulnerable to RCE:",
}


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.HIGH)
class LFIDetector(InjectionDetectorBase):
    """
    Module for detecting Local File Inclusion (LFI) vulnerabilities.
    """

    identity = "lfi_detector"

    def _pre_run_check(self, current_task: Task) -> bool:
        return self.check_connection_to_base_url_and_save_error(current_task)

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
                    for i, param in enumerate(parameters + URL_PARAMS):
                        param_batch.append(param)
                        url_with_payload = self.create_url_with_batch_payload(current_url, param_batch, payload)

                        # The idea of that check is to break down params into chunks that lead to a given maximum URL
                        # length (as longer URLs may be unsupported by the servers).
                        #
                        # We can't have constant chunk size as the payloads have varied length.
                        if len(url_with_payload) >= 1600 or i == len(URL_PARAMS) - 1:
                            response = self.http_get(url_with_payload)

                            if indicator := self.contains_lfi_indicator(original_response, response):
                                messages.append(
                                    {
                                        "url": url_with_payload,
                                        "headers": {},
                                        "matched_indicator": indicator,
                                        "statement": vulnerability_to_message[vulnerability] + " " + url_with_payload,
                                        "code": vulnerability.value,
                                    }
                                )
                                if Config.Modules.LFIDetector.LFI_STOP_ON_FIRST_MATCH:
                                    return messages
                            param_batch = []

        return messages

    def create_status_reason(self, messages: List[Dict[str, Any]]) -> str:
        return ", ".join([m["statement"] for m in messages])

    def create_data(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {"result": messages, "statements": {e.value: e.name for e in LFIFindings}}


if __name__ == "__main__":
    LFIDetector().loop()
