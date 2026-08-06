#!/usr/bin/env python3
import urllib.parse
from typing import List

from karton.core import Task

from artemis import http_requests, load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url


ORIGINS_TO_TEST = [
    "https://evil.com",
    "null",
]


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class CorsScanner(ArtemisBase):
    """
    Scans for CORS misconfigurations by testing whether the server reflects
    arbitrary Origin headers while also allowing credentials.

    A reflected origin combined with Access-Control-Allow-Credentials: true
    means any website can make authenticated cross-origin requests and read
    the responses — enabling cross-origin data theft.
    """

    identity = "cors_scanner"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _test_origin(self, url: str, origin: str) -> dict:
        """Send a request with a given Origin header and check the CORS response."""
        response = http_requests.get(url, allow_redirects=False, headers={"Origin": origin})

        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "")

        return {
            "acao": acao,
            "acac": acac,
        }

    def _is_misconfigured(self, acao: str, acac: str, test_origin: str) -> bool:
        """
        A CORS configuration is exploitable when:
        1. The server reflects the attacker's origin (or uses wildcard), AND
        2. Access-Control-Allow-Credentials is set to true

        Without credentials, the impact is limited to reading public data.
        """
        if acac.lower() != "true":
            return False

        # Reflected origin or wildcard with credentials
        return acao == test_origin or acao == "*"

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"CORS scanning {url}")

        findings: List[dict] = []

        for test_origin in ORIGINS_TO_TEST:
            try:
                cors_headers = self._test_origin(url, test_origin)
            except Exception:
                continue

            if self._is_misconfigured(cors_headers["acao"], cors_headers["acac"], test_origin):
                findings.append(
                    {
                        "reflected_origin": test_origin,
                        "acao_value": cors_headers["acao"],
                        "acac_value": cors_headers["acac"],
                        "url_tested": url,
                    }
                )

        # Also test a suffix-match bypass: https://target.evil.com
        parsed = urllib.parse.urlparse(url)
        target_host = parsed.hostname or ""
        suffix_origin = f"https://{target_host}.evil.com"
        try:
            cors_headers = self._test_origin(url, suffix_origin)
            if self._is_misconfigured(cors_headers["acao"], cors_headers["acac"], suffix_origin):
                findings.append(
                    {
                        "reflected_origin": suffix_origin,
                        "acao_value": cors_headers["acao"],
                        "acac_value": cors_headers["acac"],
                        "url_tested": url,
                    }
                )
        except Exception:
            pass

        if findings:
            status = TaskStatus.INTERESTING
            status_reason = "CORS misconfiguration: server reflects arbitrary origins with credentials enabled"
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={"findings": findings},
        )


if __name__ == "__main__":
    CorsScanner().loop()
