#!/usr/bin/env python3
import re
import urllib.parse
from typing import Any, Dict, FrozenSet, List, Set

import bs4
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.modules.data.js_secret_patterns import SECRET_PATTERNS
from artemis.task_utils import get_target_url

MAX_JS_FILES_TO_SCAN = 20
MIN_SECRET_LENGTH = 8
MAX_FINDINGS_PER_TARGET = 50

FALSE_POSITIVE_VALUES: FrozenSet[str] = frozenset(
    v.lower()
    for v in {
        "undefined",
        "null",
        "true",
        "false",
        "password",
        "changeme",
        "example",
        "your-api-key",
        "YOUR_API_KEY",
        "INSERT_YOUR_KEY_HERE",
        "xxx",
        "xxxxxxxx",
        "test",
        "TODO",
        "FIXME",
        "placeholder",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "0000000000000000",
        "1234567890abcdef",
        "sample",
        "demo",
        "dummy",
        "replace_me",
        "REPLACE_ME",
        "your_token_here",
        "your-token-here",
        "enter_your_key",
        "none",
    }
)

CDN_DOMAIN_SUFFIXES = (
    "jsdelivr.net",
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "ajax.googleapis.com",
    "code.jquery.com",
    "bootstrapcdn.com",
    "cdn.bootcss.com",
    "fonts.googleapis.com",
    "fontawesome.com",
    "google-analytics.com",
    "googletagmanager.com",
    "gstatic.com",
    "polyfill.io",
    "cloudflare.com/ajax",
    "recaptcha.net",
    "hcaptcha.com",
    "cdn.ampproject.org",
)

VENDOR_PATH_PATTERNS = re.compile(
    r"(?:jquery|angular|react|vue|bootstrap|lodash|moment|underscore|backbone|ember|"
    r"d3|chart|three|socket\.io|popper|polyfill|modernizr|normalize|reset)"
    r"[.\-](?:min\.)?(?:js|mjs)",
    re.IGNORECASE,
)

INTERNAL_URL_PATTERN = re.compile(
    r"""https?://[a-z0-9.-]+\.(?:internal|local|corp|intranet)\.[a-z]{2,}"""
    r"""|https?://(?:dev|staging|test|preprod|uat)\.[a-z0-9.-]+\.[a-z]{2,}"""
    r"""|https?://localhost:[0-9]{2,5}""",
    re.IGNORECASE,
)

ENV_VAR_PATTERN = re.compile(
    r"""(?:process\.env\.(?!NODE_ENV)[A-Z_]{3,}"""
    r"""|NEXT_PUBLIC_[A-Z_]{3,}"""
    r"""|REACT_APP_[A-Z_]{3,}"""
    r"""|VITE_[A-Z_]{3,}"""
    r"""|NUXT_PUBLIC_[A-Z_]{3,})""",
)

SOURCEMAP_COMMENT_PATTERN = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)")

WEBPACK_CHUNK_PATTERN = re.compile(
    r"""(?:"""
    r"""(?:__webpack_require__|webpackJsonp)\s*\(\s*["']([^"']+)["']"""
    r"""|["'](?:static/js|chunks?)/([a-zA-Z0-9._-]+\.js)["']"""
    r"""|\.src\s*=\s*[a-z]+\s*\+\s*["']([^"']+\.js)["']"""
    r""")""",
    re.IGNORECASE,
)


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class JSSecretScanner(ArtemisBase):
    """
    Scans JavaScript files for hardcoded secrets such as API keys, tokens, and credentials.
    Also detects exposed source maps, webpack chunks, internal URLs, and environment variable leaks.
    """

    identity = "js_secret_scanner"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _extract_js_urls(self, url: str, html_content: str) -> List[str]:
        js_urls: List[str] = []
        seen: Set[str] = set()

        try:
            soup = bs4.BeautifulSoup(html_content, "html.parser")
        except Exception:
            return []

        for script_tag in soup.find_all("script", src=True):
            src = script_tag.get("src", "")
            if not src or not src.strip():
                continue

            src = src.strip()
            absolute_url = urllib.parse.urljoin(url, src)
            parsed = urllib.parse.urlparse(absolute_url)

            if parsed.scheme not in ("http", "https"):
                continue

            normalized = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
            )

            if normalized in seen:
                continue
            seen.add(normalized)

            if self._is_cdn_or_vendor(parsed.netloc, parsed.path):
                continue

            js_urls.append(absolute_url)

            if len(js_urls) >= MAX_JS_FILES_TO_SCAN:
                break

        return js_urls

    @staticmethod
    def _is_cdn_or_vendor(netloc: str, path: str) -> bool:
        netloc_lower = netloc.lower()
        for suffix in CDN_DOMAIN_SUFFIXES:
            if netloc_lower == suffix or netloc_lower.endswith("." + suffix):
                return True

        if VENDOR_PATH_PATTERNS.search(path.lower()):
            return True

        return False

    def _discover_webpack_chunks(self, url: str, js_content: str) -> List[str]:
        chunk_urls: List[str] = []
        base_url = url.rsplit("/", 1)[0] + "/" if "/" in url else url + "/"

        for match in WEBPACK_CHUNK_PATTERN.finditer(js_content):
            chunk_path = match.group(1) or match.group(2) or match.group(3)
            if not chunk_path:
                continue
            chunk_url = urllib.parse.urljoin(base_url, chunk_path)
            if chunk_url not in chunk_urls:
                chunk_urls.append(chunk_url)

        return chunk_urls[:5]

    def _check_source_map(self, js_url: str, js_content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        map_match = SOURCEMAP_COMMENT_PATTERN.search(js_content)
        if map_match:
            map_ref = map_match.group(1)
            if map_ref.startswith("data:"):
                return findings

            map_url = urllib.parse.urljoin(js_url, map_ref)
            try:
                map_response = self.http_get(map_url)
                content_type = map_response.headers.get("Content-Type", "")
                if (
                    map_response.status_code == 200
                    and ("json" in content_type or map_response.content.strip().startswith("{"))
                ):
                    findings.append(
                        {
                            "pattern_name": "Exposed Source Map",
                            "severity": "medium",
                            "js_url": js_url,
                            "matched_text_redacted": map_url[:60] + "..." if len(map_url) > 60 else map_url,
                            "match_start": map_match.start(),
                        }
                    )
            except Exception:
                pass
        else:
            map_url = js_url + ".map"
            try:
                map_response = self.http_get(map_url)
                content_type = map_response.headers.get("Content-Type", "")
                if (
                    map_response.status_code == 200
                    and ("json" in content_type or map_response.content.strip().startswith("{"))
                ):
                    findings.append(
                        {
                            "pattern_name": "Exposed Source Map",
                            "severity": "medium",
                            "js_url": js_url,
                            "matched_text_redacted": map_url[:60] + "..." if len(map_url) > 60 else map_url,
                            "match_start": 0,
                        }
                    )
            except Exception:
                pass

        return findings

    def _detect_env_var_exposure(self, js_url: str, content: str, global_seen: Set[str]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for match in ENV_VAR_PATTERN.finditer(content):
            var_name = match.group(0)
            dedup_key = f"env_var_exposure:{var_name}"
            if dedup_key in global_seen:
                continue
            global_seen.add(dedup_key)

            findings.append(
                {
                    "pattern_name": "Environment Variable Exposure",
                    "severity": "medium",
                    "js_url": js_url,
                    "matched_text_redacted": var_name,
                    "match_start": match.start(),
                }
            )

        return findings

    def _detect_internal_urls(self, js_url: str, content: str, global_seen: Set[str]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for match in INTERNAL_URL_PATTERN.finditer(content):
            matched_url = match.group(0)
            dedup_key = f"internal_url:{matched_url}"
            if dedup_key in global_seen:
                continue
            global_seen.add(dedup_key)

            if len(matched_url) > 16:
                redacted = matched_url[:12] + "..." + matched_url[-4:]
            else:
                redacted = matched_url[:8] + "..."

            findings.append(
                {
                    "pattern_name": "Internal URL Exposure",
                    "severity": "medium",
                    "js_url": js_url,
                    "matched_text_redacted": redacted,
                    "match_start": match.start(),
                }
            )

        return findings

    def _scan_js_content(self, js_url: str, content: str, global_seen: Set[str]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for pattern in SECRET_PATTERNS:
            for match in pattern.regex.finditer(content):
                matched_text = match.group(0).strip()

                if len(matched_text) < MIN_SECRET_LENGTH:
                    continue

                core_value = matched_text
                for quote in ('"', "'"):
                    last_start = core_value.rfind(quote)
                    first_end = core_value.find(quote)
                    if first_end != -1 and last_start > first_end:
                        core_value = core_value[first_end + 1 : last_start]
                        break
                else:
                    core_value = core_value.strip("\"' \t\n\r")

                if core_value.lower() in FALSE_POSITIVE_VALUES:
                    continue

                if len(set(core_value)) <= 2:
                    continue

                dedup_key = f"{pattern.name}:{core_value}"
                if dedup_key in global_seen:
                    continue
                global_seen.add(dedup_key)

                if len(matched_text) > 16:
                    redacted = matched_text[:8] + "..." + matched_text[-4:]
                elif len(matched_text) > 12:
                    redacted = matched_text[:6] + "..." + matched_text[-3:]
                else:
                    redacted = matched_text[:6] + "..."

                findings.append(
                    {
                        "pattern_name": pattern.name,
                        "severity": pattern.severity,
                        "js_url": js_url,
                        "matched_text_redacted": redacted,
                        "match_start": match.start(),
                    }
                )

        return findings

    def _scan_inline_scripts(self, url: str, html_content: str, global_seen: Set[str]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        try:
            soup = bs4.BeautifulSoup(html_content, "html.parser")
        except Exception:
            return []

        for idx, script_tag in enumerate(soup.find_all("script", src=False)):
            script_content = script_tag.string
            if not script_content or len(script_content) < 50:
                continue

            inline_label = f"{url} (inline-{idx})"
            inline_findings = self._scan_js_content(inline_label, script_content, global_seen)
            findings.extend(inline_findings)

            env_findings = self._detect_env_var_exposure(inline_label, script_content, global_seen)
            findings.extend(env_findings)

            url_findings = self._detect_internal_urls(inline_label, script_content, global_seen)
            findings.extend(url_findings)

        return findings

    def _scan_external_js(
        self, js_url: str, global_seen: Set[str], scanned_urls: Set[str]
    ) -> List[Dict[str, Any]]:
        if js_url in scanned_urls:
            return []
        scanned_urls.add(js_url)

        findings: List[Dict[str, Any]] = []

        try:
            js_response = self.http_get(js_url)
            js_content = js_response.content

            if not js_content:
                return []

            content_type = js_response.headers.get("Content-Type", "")
            if content_type and "html" in content_type.lower() and "javascript" not in content_type.lower():
                self.log.debug(f"Skipping {js_url}: Content-Type is {content_type}")
                return []

            file_findings = self._scan_js_content(js_url, js_content, global_seen)
            findings.extend(file_findings)

            env_findings = self._detect_env_var_exposure(js_url, js_content, global_seen)
            findings.extend(env_findings)

            url_findings = self._detect_internal_urls(js_url, js_content, global_seen)
            findings.extend(url_findings)

            sourcemap_findings = self._check_source_map(js_url, js_content)
            for sf in sourcemap_findings:
                dedup_key = f"sourcemap:{sf['matched_text_redacted']}"
                if dedup_key not in global_seen:
                    global_seen.add(dedup_key)
                    findings.extend([sf])

            chunk_urls = self._discover_webpack_chunks(js_url, js_content)
            for chunk_url in chunk_urls:
                if len(findings) >= MAX_FINDINGS_PER_TARGET:
                    break
                chunk_findings = self._scan_external_js(chunk_url, global_seen, scanned_urls)
                findings.extend(chunk_findings)

        except Exception:
            self.log.debug(f"Failed to fetch JS file: {js_url}")

        return findings

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"JS Secret Scanner checking {url}")

        all_findings: List[Dict[str, Any]] = []
        global_seen: Set[str] = set()
        scanned_urls: Set[str] = set()

        try:
            response = self.http_get(url)
        except Exception:
            self.log.info(f"Failed to fetch {url}, skipping JS secret scan")
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.OK,
                status_reason=None,
                data={"findings": [], "error": "target_unreachable"},
            )
            return

        html_content = response.content

        inline_findings = self._scan_inline_scripts(url, html_content, global_seen)
        all_findings.extend(inline_findings)

        js_urls = self._extract_js_urls(url, html_content)
        self.log.info(f"Found {len(js_urls)} JS files to scan on {url}")

        for js_url in js_urls:
            if len(all_findings) >= MAX_FINDINGS_PER_TARGET:
                self.log.info(f"Reached max findings limit ({MAX_FINDINGS_PER_TARGET}), stopping scan")
                break

            js_findings = self._scan_external_js(js_url, global_seen, scanned_urls)
            all_findings.extend(js_findings)

        all_findings = all_findings[:MAX_FINDINGS_PER_TARGET]

        if all_findings:
            pattern_names = sorted(set(f["pattern_name"] for f in all_findings))
            high_count = sum(1 for f in all_findings if f["severity"] == "high")
            status = TaskStatus.INTERESTING
            status_reason = f"Found {len(all_findings)} secret(s) ({high_count} high severity): " + ", ".join(
                pattern_names
            )
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={
                "findings": all_findings,
                "js_files_scanned": len(scanned_urls),
                "inline_scripts_scanned": True,
            },
        )


if __name__ == "__main__":
    JSSecretScanner().loop()
