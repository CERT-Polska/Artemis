#!/usr/bin/env python3
import dataclasses
import urllib.parse
from typing import Any, Dict, List, Optional

from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url


@dataclasses.dataclass
class CORSFinding:
    issue: str
    origin_sent: str
    acao_header: str
    acac_header: Optional[str]
    request_method: str


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class CORSScanner(ArtemisBase):
    """
    Checks for CORS misconfigurations that could allow unauthorized cross-origin access.
    """

    identity = "cors_scanner"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _check_cors_simple(self, url: str, origin: str) -> Optional[CORSFinding]:
        try:
            response = self.http_get(url, headers={"Origin": origin})
        except Exception:
            return None

        return self._analyze_cors_headers(response.headers, origin, "GET")

    def _check_cors_preflight(self, url: str, origin: str) -> Optional[CORSFinding]:
        try:
            response = self.http_get(
                url,
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "PUT",
                    "Access-Control-Request-Headers": "X-Custom-Header, Authorization",
                },
            )
        except Exception:
            return None

        return self._analyze_cors_headers(response.headers, origin, "OPTIONS")

    def _analyze_cors_headers(
        self, headers: Dict[str, str], origin: str, request_method: str
    ) -> Optional[CORSFinding]:
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")

        if not acao:
            return None

        # Browsers block this combination, but its presence indicates misconfiguration
        if acao == "*" and acac.lower() == "true":
            return CORSFinding(
                issue="wildcard_with_credentials",
                origin_sent=origin,
                acao_header=acao,
                acac_header=acac,
                request_method=request_method,
            )

        if acao == origin and origin != "null":
            return CORSFinding(
                issue="arbitrary_origin_reflected",
                origin_sent=origin,
                acao_header=acao,
                acac_header=acac if acac else None,
                request_method=request_method,
            )

        # Null origin exploitable via sandboxed iframes, data: URIs, file: protocol
        if acao == "null" and origin == "null" and acac.lower() == "true":
            return CORSFinding(
                issue="null_origin_with_credentials",
                origin_sent=origin,
                acao_header=acao,
                acac_header=acac,
                request_method=request_method,
            )

        return None

    def _generate_test_origins(self, url: str) -> List[Dict[str, str]]:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        scheme = parsed.scheme or "https"

        tests = [
            {"name": "arbitrary_origin_reflected", "origin": "https://evil-attacker.com"},
            {"name": "null_origin_allowed", "origin": "null"},
            {"name": "prefix_match_bypass", "origin": f"{scheme}://{hostname}.evil.com"},
            {"name": "suffix_match_bypass", "origin": f"{scheme}://evil{hostname}"},
            {"name": "subdomain_bypass", "origin": f"{scheme}://attacker.{hostname}"},
        ]

        if scheme == "https":
            tests.append({"name": "http_scheme_bypass", "origin": f"http://{hostname}"})

        return tests

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"CORS scanner checking {url}")

        try:
            self.http_get(url)
        except Exception:
            self.log.info(f"Target {url} is not reachable, skipping CORS checks")
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.OK,
                status_reason=None,
                data={"findings": [], "error": "target_unreachable"},
            )
            return

        findings: List[Dict[str, Any]] = []
        seen_issues: set = set()

        for test in self._generate_test_origins(url):
            finding = self._check_cors_simple(url, test["origin"])
            if finding:
                dedup_key = f"{finding.issue}:{finding.origin_sent}"
                if dedup_key not in seen_issues:
                    seen_issues.add(dedup_key)
                    findings.append(dataclasses.asdict(finding))
                    self.log.info(f"CORS issue found: {finding.issue} on {url} with origin {test['origin']} (GET)")

            preflight_finding = self._check_cors_preflight(url, test["origin"])
            if preflight_finding:
                dedup_key = f"{preflight_finding.issue}:{preflight_finding.origin_sent}"
                if dedup_key not in seen_issues:
                    seen_issues.add(dedup_key)
                    findings.append(dataclasses.asdict(preflight_finding))
                    self.log.info(
                        f"CORS issue found: {preflight_finding.issue} on {url} "
                        f"with origin {test['origin']} (OPTIONS)"
                    )

        if findings:
            status = TaskStatus.INTERESTING
            finding_issues = sorted(set(f["issue"] for f in findings))
            status_reason = "CORS misconfiguration detected: " + ", ".join(finding_issues)
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
    CORSScanner().loop()
