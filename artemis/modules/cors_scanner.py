#!/usr/bin/env python3
import dataclasses
import urllib.parse
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from karton.core import Task

from artemis import http_requests, load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.crawling import get_links_and_resources_on_same_domain
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_DESCRIPTIONS: Dict[str, str] = {
    "wildcard_with_credentials": (
        "Access-Control-Allow-Origin is set to * with Access-Control-Allow-Credentials: true. "
        "Browsers block this combination, but it signals a fundamental misunderstanding of CORS "
        "and may indicate other misconfigurations."
    ),
    "arbitrary_origin_reflected": (
        "The server reflects any Origin header value in Access-Control-Allow-Origin. "
        "An attacker can host a malicious page that makes authenticated cross-origin requests "
        "and reads the response, leading to full data exfiltration."
    ),
    "null_origin_with_credentials": (
        "The server allows the 'null' origin with credentials. Sandboxed iframes, data: URIs, "
        "and redirects send Origin: null. An attacker can exploit this to bypass CORS restrictions."
    ),
    "prefix_bypass": (
        "The server validates origins using prefix matching. An attacker can register a domain "
        "that starts with the trusted domain name."
    ),
    "suffix_bypass": (
        "The server validates origins using suffix matching. An attacker can register a domain "
        "that ends with the trusted domain name."
    ),
    "subdomain_bypass": (
        "The server trusts all subdomains. If any subdomain is compromised via XSS "
        "or subdomain takeover, an attacker can make authenticated cross-origin requests."
    ),
    "special_char_bypass": (
        "The server's origin validation can be bypassed using special characters like "
        "underscores, backticks, or unescaped dots in the hostname."
    ),
    "http_downgrade": (
        "An HTTPS endpoint accepts CORS requests from an HTTP origin. A network attacker "
        "performing MITM can inject malicious JavaScript on the HTTP origin to steal data."
    ),
    "third_party_domain_trusted": (
        "The server trusts origins on shared hosting platforms. "
        "Anyone can create a subdomain on these platforms and make authenticated requests."
    ),
    "missing_vary_origin": (
        "The server reflects the Origin in Access-Control-Allow-Origin but does not include "
        "Vary: Origin, allowing CDN/proxy cache poisoning."
    ),
    "dangerous_methods_allowed": (
        "The preflight response allows dangerous HTTP methods (PUT, DELETE, PATCH) from "
        "untrusted origins, enabling state-changing cross-origin requests."
    ),
    "sensitive_headers_allowed": (
        "The preflight response allows sensitive headers (Authorization, Cookie, X-CSRF-Token) "
        "from untrusted origins, enabling credential-bearing cross-origin requests."
    ),
    "excessive_max_age": (
        "Access-Control-Max-Age is set to an excessively high value. If the CORS policy is "
        "later tightened, clients won't pick up the change until the cache expires."
    ),
    "expose_sensitive_headers": (
        "Access-Control-Expose-Headers includes sensitive headers that are readable by "
        "cross-origin JavaScript, potentially leaking security tokens or session data."
    ),
}


def _classify_severity(issue: str, credentials: bool) -> Severity:
    critical_with_creds = {"arbitrary_origin_reflected", "null_origin_with_credentials"}
    high_with_creds = {
        "prefix_bypass", "suffix_bypass", "subdomain_bypass",
        "special_char_bypass", "third_party_domain_trusted",
    }

    if issue in critical_with_creds and credentials:
        return Severity.CRITICAL
    if issue in critical_with_creds:
        return Severity.HIGH
    if issue in high_with_creds and credentials:
        return Severity.HIGH
    if issue in high_with_creds:
        return Severity.MEDIUM
    if issue == "http_downgrade" and credentials:
        return Severity.HIGH
    if issue == "http_downgrade":
        return Severity.MEDIUM
    if issue in ("dangerous_methods_allowed", "sensitive_headers_allowed"):
        return Severity.MEDIUM
    if issue in ("missing_vary_origin", "excessive_max_age", "expose_sensitive_headers"):
        return Severity.LOW
    if issue == "wildcard_with_credentials":
        return Severity.MEDIUM
    return Severity.INFO


@dataclasses.dataclass
class CORSFinding:
    issue: str
    severity: str
    description: str
    origin_sent: str
    acao_header: str
    acac_header: Optional[str]
    request_method: str
    endpoint: str
    details: Optional[str] = None

    @staticmethod
    def create(
        issue: str,
        origin_sent: str,
        acao_header: str,
        acac_header: Optional[str],
        request_method: str,
        endpoint: str,
        details: Optional[str] = None,
    ) -> "CORSFinding":
        credentials = acac_header is not None and acac_header.lower() == "true"
        severity = _classify_severity(issue, credentials)
        description = SEVERITY_DESCRIPTIONS.get(issue, issue)
        return CORSFinding(
            issue=issue,
            severity=severity.value,
            description=description,
            origin_sent=origin_sent,
            acao_header=acao_header,
            acac_header=acac_header,
            request_method=request_method,
            endpoint=endpoint,
            details=details,
        )


THIRD_PARTY_TRUST_DOMAINS = [
    "github.io", "herokuapp.com", "repl.it", "replit.dev",
    "netlify.app", "vercel.app", "surge.sh", "glitch.me",
    "firebaseapp.com", "web.app", "azurewebsites.net", "cloudfront.net",
    "pages.dev", "workers.dev", "fly.dev", "render.com",
    "onrender.com", "railway.app", "gitpod.io", "codepen.io",
    "jsbin.com", "jsfiddle.net", "stackblitz.io", "codesandbox.io",
    "ngrok.io", "ngrok-free.app", "loca.lt", "trycloudflare.com",
]

DANGEROUS_METHODS = {"PUT", "DELETE", "PATCH"}
SENSITIVE_HEADERS = {"authorization", "x-api-key", "x-csrf-token", "cookie", "x-auth-token"}
SENSITIVE_EXPOSE_HEADERS = {"set-cookie", "authorization", "x-csrf-token", "x-auth-token"}
MAX_ENDPOINTS_PER_TARGET = 15
EXCESSIVE_MAX_AGE_SECONDS = 604800


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class CORSScanner(ArtemisBase):
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

    def _get_with_origin(self, url: str, origin: str) -> Optional[http_requests.HTTPResponse]:
        try:
            return self.http_get(url, headers={"Origin": origin})
        except Exception:
            return None

    def _post_with_origin(self, url: str, origin: str) -> Optional[http_requests.HTTPResponse]:
        try:
            return self.http_post(url, headers={"Origin": origin})
        except Exception:
            return None

    def _analyze_cors_headers(
        self, headers: Dict[str, str], origin: str, method: str, endpoint: str, issue_hint: str
    ) -> Optional[CORSFinding]:
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")

        if not acao:
            return None

        if acao == "*" and acac.lower() == "true":
            return CORSFinding.create(
                issue="wildcard_with_credentials",
                origin_sent=origin, acao_header=acao, acac_header=acac,
                request_method=method, endpoint=endpoint,
            )

        if acao == origin and origin != "null":
            return CORSFinding.create(
                issue=issue_hint,
                origin_sent=origin, acao_header=acao,
                acac_header=acac if acac else None,
                request_method=method, endpoint=endpoint,
            )

        if acao == "null" and origin == "null" and acac.lower() == "true":
            return CORSFinding.create(
                issue="null_origin_with_credentials",
                origin_sent=origin, acao_header=acao, acac_header=acac,
                request_method=method, endpoint=endpoint,
            )

        return None

    def _check_preflight_permissions(
        self, headers: Dict[str, str], origin: str, endpoint: str
    ) -> List[CORSFinding]:
        findings: List[CORSFinding] = []
        acao = headers.get("Access-Control-Allow-Origin", "")
        if not acao or (acao != "*" and acao != origin):
            return findings

        acac = headers.get("Access-Control-Allow-Credentials")

        acam = headers.get("Access-Control-Allow-Methods", "")
        if acam:
            allowed = {m.strip().upper() for m in acam.split(",")}
            dangerous = allowed & DANGEROUS_METHODS
            if dangerous:
                findings.append(CORSFinding.create(
                    issue="dangerous_methods_allowed",
                    origin_sent=origin, acao_header=acao, acac_header=acac,
                    request_method="OPTIONS", endpoint=endpoint,
                    details=f"Allowed dangerous methods: {', '.join(sorted(dangerous))}",
                ))

        acah = headers.get("Access-Control-Allow-Headers", "")
        if acah:
            allowed_h = {h.strip().lower() for h in acah.split(",")}
            sensitive = allowed_h & SENSITIVE_HEADERS
            if sensitive:
                findings.append(CORSFinding.create(
                    issue="sensitive_headers_allowed",
                    origin_sent=origin, acao_header=acao, acac_header=acac,
                    request_method="OPTIONS", endpoint=endpoint,
                    details=f"Allowed sensitive headers: {', '.join(sorted(sensitive))}",
                ))

        max_age = headers.get("Access-Control-Max-Age", "")
        if max_age:
            try:
                if int(max_age) > EXCESSIVE_MAX_AGE_SECONDS:
                    findings.append(CORSFinding.create(
                        issue="excessive_max_age",
                        origin_sent=origin, acao_header=acao, acac_header=acac,
                        request_method="OPTIONS", endpoint=endpoint,
                        details=f"Max-Age: {max_age}s ({int(max_age) // 86400} days)",
                    ))
            except ValueError:
                pass

        return findings

    def _check_expose_headers(
        self, headers: Dict[str, str], origin: str, endpoint: str
    ) -> Optional[CORSFinding]:
        aceh = headers.get("Access-Control-Expose-Headers", "")
        if not aceh:
            return None
        exposed = {h.strip().lower() for h in aceh.split(",")}
        sensitive = exposed & SENSITIVE_EXPOSE_HEADERS
        if sensitive:
            return CORSFinding.create(
                issue="expose_sensitive_headers",
                origin_sent=origin,
                acao_header=headers.get("Access-Control-Allow-Origin", ""),
                acac_header=headers.get("Access-Control-Allow-Credentials"),
                request_method="GET", endpoint=endpoint,
                details=f"Exposed sensitive headers: {', '.join(sorted(sensitive))}",
            )
        return None

    def _check_origin(self, endpoint: str, origin: str, issue_hint: str) -> List[CORSFinding]:
        findings: List[CORSFinding] = []

        resp = self._get_with_origin(endpoint, origin)
        if resp:
            f = self._analyze_cors_headers(resp.headers, origin, "GET", endpoint, issue_hint)
            if f:
                findings.append(f)
            ef = self._check_expose_headers(resp.headers, origin, endpoint)
            if ef:
                findings.append(ef)

        resp = self._post_with_origin(endpoint, origin)
        if resp:
            f = self._analyze_cors_headers(resp.headers, origin, "POST", endpoint, issue_hint)
            if f:
                findings.append(f)

        resp = self._send_options(endpoint, origin)
        if resp:
            f = self._analyze_cors_headers(resp.headers, origin, "OPTIONS", endpoint, issue_hint)
            if f:
                findings.append(f)
            findings.extend(self._check_preflight_permissions(resp.headers, origin, endpoint))

        return findings

    def _check_vary_origin(self, endpoint: str) -> Optional[CORSFinding]:
        probe_origin = "https://cors-vary-probe.example.com"
        resp = self._get_with_origin(endpoint, probe_origin)
        if resp is None:
            return None

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if not acao or acao == "*" or acao != probe_origin:
            return None

        vary = resp.headers.get("Vary", "")
        if "origin" not in vary.lower():
            return CORSFinding.create(
                issue="missing_vary_origin",
                origin_sent=probe_origin, acao_header=acao,
                acac_header=resp.headers.get("Access-Control-Allow-Credentials"),
                request_method="GET", endpoint=endpoint,
                details="Reflects Origin in ACAO but missing Vary: Origin",
            )
        return None

    def _check_third_party_trust(self, endpoint: str) -> List[CORSFinding]:
        findings: List[CORSFinding] = []
        for domain in THIRD_PARTY_TRUST_DOMAINS:
            origin = f"https://attacker.{domain}"
            resp = self._get_with_origin(endpoint, origin)
            if resp is None:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == origin:
                findings.append(CORSFinding.create(
                    issue="third_party_domain_trusted",
                    origin_sent=origin, acao_header=acao,
                    acac_header=acac if acac else None,
                    request_method="GET", endpoint=endpoint,
                    details=f"Trusts user-controlled hosting on {domain}",
                ))
                break

        return findings

    def _generate_test_origins(self, url: str) -> List[Dict[str, str]]:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        scheme = parsed.scheme or "https"

        tests = [
            {"hint": "arbitrary_origin_reflected", "origin": "https://evil-attacker.com"},
            {"hint": "null_origin_with_credentials", "origin": "null"},
            {"hint": "prefix_bypass", "origin": f"{scheme}://{hostname}.evil.com"},
            {"hint": "suffix_bypass", "origin": f"{scheme}://evil{hostname}"},
            {"hint": "subdomain_bypass", "origin": f"{scheme}://attacker.{hostname}"},
            {"hint": "special_char_bypass", "origin": f"{scheme}://{hostname}_.evil.com"},
            {"hint": "special_char_bypass", "origin": f"{scheme}://{hostname}`.evil.com"},
            {"hint": "special_char_bypass", "origin": f"{scheme}://evil{hostname.replace('.', 'X', 1)}"},
        ]

        if scheme == "https":
            tests.append({"hint": "http_downgrade", "origin": f"http://{hostname}"})

        return tests

    def _collect_endpoints(self, url: str) -> List[str]:
        endpoints: List[str] = [url]
        try:
            links = get_links_and_resources_on_same_domain(url)
            for link in links:
                parsed = urllib.parse.urlparse(link)
                path = parsed.path.lower()
                if any(path.endswith(ext) for ext in (
                    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
                )):
                    continue
                if link not in endpoints:
                    endpoints.append(link)
                if len(endpoints) >= MAX_ENDPOINTS_PER_TARGET:
                    break
        except Exception as e:
            self.log.warning(f"Crawling failed for {url}: {e}")

        return endpoints

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"CORS scanner starting on {url}")

        try:
            self.http_get(url)
        except Exception:
            self.log.info(f"Target {url} unreachable, skipping")
            self.db.save_task_result(
                task=current_task, status=TaskStatus.OK, status_reason=None,
                data={"findings": [], "endpoints_scanned": 0, "error": "target_unreachable"},
            )
            return

        endpoints = self._collect_endpoints(url)
        self.log.info(f"Scanning {len(endpoints)} endpoint(s) on {url}")

        all_findings: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        def _add(finding: CORSFinding) -> None:
            dedup = f"{finding.issue}:{finding.origin_sent}:{finding.endpoint}"
            if dedup not in seen:
                seen.add(dedup)
                all_findings.append(dataclasses.asdict(finding))
                self.log.info(
                    f"[{finding.severity.upper()}] {finding.issue} on {finding.endpoint} "
                    f"(origin={finding.origin_sent}, method={finding.request_method})"
                )

        for endpoint in endpoints:
            for test in self._generate_test_origins(url):
                for f in self._check_origin(endpoint, test["origin"], test["hint"]):
                    _add(f)

            vary_f = self._check_vary_origin(endpoint)
            if vary_f:
                _add(vary_f)

            if endpoint == url:
                for f in self._check_third_party_trust(endpoint):
                    _add(f)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        all_findings.sort(key=lambda f: severity_order.get(f["severity"], 5))

        severity_counts: Dict[str, int] = {}
        for f in all_findings:
            severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

        if all_findings:
            status = TaskStatus.INTERESTING
            summary_parts = [f"{count} {sev}" for sev, count in sorted(
                severity_counts.items(), key=lambda x: severity_order.get(x[0], 5)
            )]
            status_reason = f"CORS misconfigurations found: {', '.join(summary_parts)}"
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=current_task, status=status, status_reason=status_reason,
            data={
                "findings": all_findings,
                "endpoints_scanned": len(endpoints),
                "severity_counts": severity_counts,
            },
        )


if __name__ == "__main__":
    CORSScanner().loop()
