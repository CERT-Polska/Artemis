#!/usr/bin/env python3
import dataclasses
import urllib.parse
from typing import Any, Dict, List, Optional

from karton.core import Task

from artemis import http_requests, load_risk_class
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
    details: Optional[str] = None


THIRD_PARTY_TRUST_DOMAINS = [
    "github.io",
    "herokuapp.com",
    "repl.it",
    "replit.dev",
    "netlify.app",
    "vercel.app",
    "surge.sh",
    "glitch.me",
    "firebaseapp.com",
    "web.app",
    "azurewebsites.net",
    "cloudfront.net",
    "pages.dev",
    "workers.dev",
    "fly.dev",
    "render.com",
    "onrender.com",
    "railway.app",
    "gitpod.io",
    "codepen.io",
    "jsbin.com",
    "jsfiddle.net",
]

DANGEROUS_METHODS = {"PUT", "DELETE", "PATCH"}
SENSITIVE_HEADERS = {"authorization", "x-api-key", "x-csrf-token", "cookie"}


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class CORSScanner(ArtemisBase):
    """
    Checks for CORS misconfigurations that could allow unauthorized cross-origin access.
    Tests simple requests, preflight OPTIONS, and POST methods against crafted origins
    including special character bypasses and third-party domain trust checks.
    """

    identity = "cors_scanner"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _send_options(self, url: str, origin: str) -> Optional[http_requests.HTTPResponse]:
        try:
            return http_requests.request(
                "options",
                url,
                requests_per_second=self.requests_per_second_for_current_tasks,
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "PUT",
                    "Access-Control-Request-Headers": "Authorization, X-Custom-Header",
                },
            )
        except Exception:
            return None

    def _check_cors_simple(self, url: str, origin: str) -> Optional[CORSFinding]:
        try:
            response = self.http_get(url, headers={"Origin": origin})
        except Exception:
            return None

        return self._analyze_cors_headers(response.headers, origin, "GET")

    def _check_cors_post(self, url: str, origin: str) -> Optional[CORSFinding]:
        try:
            response = self.http_post(url, headers={"Origin": origin})
        except Exception:
            return None

        return self._analyze_cors_headers(response.headers, origin, "POST")

    def _check_cors_preflight(self, url: str, origin: str) -> Optional[CORSFinding]:
        response = self._send_options(url, origin)
        if response is None:
            return None

        finding = self._analyze_cors_headers(response.headers, origin, "OPTIONS")
        if finding:
            return finding

        return self._check_preflight_permissions(response.headers, origin)

    def _check_preflight_permissions(
        self, headers: Dict[str, str], origin: str
    ) -> Optional[CORSFinding]:
        acao = headers.get("Access-Control-Allow-Origin", "")
        if not acao or (acao != "*" and acao != origin):
            return None

        acam = headers.get("Access-Control-Allow-Methods", "")
        if acam:
            allowed_methods = {m.strip().upper() for m in acam.split(",")}
            dangerous_allowed = allowed_methods & DANGEROUS_METHODS
            if dangerous_allowed:
                return CORSFinding(
                    issue="dangerous_methods_allowed",
                    origin_sent=origin,
                    acao_header=acao,
                    acac_header=headers.get("Access-Control-Allow-Credentials"),
                    request_method="OPTIONS",
                    details=f"Methods: {', '.join(sorted(dangerous_allowed))}",
                )

        acah = headers.get("Access-Control-Allow-Headers", "")
        if acah:
            allowed_headers = {h.strip().lower() for h in acah.split(",")}
            sensitive_allowed = allowed_headers & SENSITIVE_HEADERS
            if sensitive_allowed:
                return CORSFinding(
                    issue="sensitive_headers_allowed",
                    origin_sent=origin,
                    acao_header=acao,
                    acac_header=headers.get("Access-Control-Allow-Credentials"),
                    request_method="OPTIONS",
                    details=f"Headers: {', '.join(sorted(sensitive_allowed))}",
                )

        return None

    def _analyze_cors_headers(
        self, headers: Dict[str, str], origin: str, request_method: str
    ) -> Optional[CORSFinding]:
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")

        if not acao:
            return None

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

        if acao == "null" and origin == "null" and acac.lower() == "true":
            return CORSFinding(
                issue="null_origin_with_credentials",
                origin_sent=origin,
                acao_header=acao,
                acac_header=acac,
                request_method=request_method,
            )

        return None

    def _check_vary_origin(self, url: str) -> Optional[CORSFinding]:
        try:
            resp1 = self.http_get(url, headers={"Origin": "https://test-a.example.com"})
        except Exception:
            return None

        acao = resp1.headers.get("Access-Control-Allow-Origin", "")
        if not acao or acao == "*":
            return None

        if acao == "https://test-a.example.com":
            vary = resp1.headers.get("Vary", "")
            if "origin" not in vary.lower():
                return CORSFinding(
                    issue="missing_vary_origin",
                    origin_sent="https://test-a.example.com",
                    acao_header=acao,
                    acac_header=resp1.headers.get("Access-Control-Allow-Credentials"),
                    request_method="GET",
                    details="Response reflects origin but missing Vary: Origin header (cache poisoning risk)",
                )

        return None

    def _check_third_party_trust(self, url: str) -> List[CORSFinding]:
        findings: List[CORSFinding] = []
        for domain in THIRD_PARTY_TRUST_DOMAINS:
            origin = f"https://attacker.{domain}"
            try:
                response = self.http_get(url, headers={"Origin": origin})
            except Exception:
                continue

            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")

            if acao == origin:
                findings.append(
                    CORSFinding(
                        issue="third_party_domain_trusted",
                        origin_sent=origin,
                        acao_header=acao,
                        acac_header=acac if acac else None,
                        request_method="GET",
                        details=f"Trusts user-controlled hosting on {domain}",
                    )
                )
                break

        return findings

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
            {"name": "unescaped_dot_bypass", "origin": f"{scheme}://evil{hostname.replace('.', 'X', 1)}"},
            {"name": "underscore_bypass", "origin": f"{scheme}://{hostname}_.evil.com"},
            {"name": "backtick_bypass", "origin": f"{scheme}://{hostname}`.evil.com"},
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
            for check_fn in (self._check_cors_simple, self._check_cors_post, self._check_cors_preflight):
                finding = check_fn(url, test["origin"])
                if finding:
                    dedup_key = f"{finding.issue}:{finding.origin_sent}"
                    if dedup_key not in seen_issues:
                        seen_issues.add(dedup_key)
                        findings.append(dataclasses.asdict(finding))
                        self.log.info(
                            f"CORS issue found: {finding.issue} on {url} "
                            f"with origin {test['origin']} ({finding.request_method})"
                        )

        vary_finding = self._check_vary_origin(url)
        if vary_finding:
            dedup_key = f"{vary_finding.issue}:{vary_finding.origin_sent}"
            if dedup_key not in seen_issues:
                seen_issues.add(dedup_key)
                findings.append(dataclasses.asdict(vary_finding))

        for tp_finding in self._check_third_party_trust(url):
            dedup_key = f"{tp_finding.issue}:{tp_finding.origin_sent}"
            if dedup_key not in seen_issues:
                seen_issues.add(dedup_key)
                findings.append(dataclasses.asdict(tp_finding))

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
