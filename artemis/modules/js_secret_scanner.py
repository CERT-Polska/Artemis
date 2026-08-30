#!/usr/bin/env python3
import math
import re
import time
import urllib.parse
from typing import Any, Dict, FrozenSet, List, Optional, Set

import bs4
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.modules.data.js_secret_patterns import SECRET_PATTERNS
from artemis.task_utils import get_target_url

MAX_JS_FILES_TO_SCAN = 20
MAX_JS_FILE_SIZE = 5 * 1024 * 1024
MIN_SECRET_LENGTH = 8
MAX_FINDINGS_PER_TARGET = 50
MAX_WEBPACK_CHUNKS = 5
ENTROPY_THRESHOLD_HEX = 2.5
ENTROPY_THRESHOLD_GENERIC = 3.0

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
        "secret",
        "default",
        "change_me",
        "my_secret",
        "my_password",
        "admin",
        "root",
        "pass",
        "token",
        "key",
        "value",
        "config",
        "setting",
        "empty",
        "blank",
        "temp",
        "tmp",
        "development",
        "staging",
    }
)

FALSE_POSITIVE_SUFFIXES = (
    ".js",
    ".css",
    ".html",
    ".png",
    ".jpg",
    ".svg",
    ".gif",
    ".woff",
    ".ttf",
    ".eot",
    ".map",
    ".json",
    ".xml",
    ".ico",
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

MINIFIED_VAR_PATTERN = re.compile(r"^[a-z]{1,2}\d*$")


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _is_hex_string(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s))


def _extract_core_value(matched_text: str) -> str:
    core = matched_text
    for quote in ('"', "'"):
        last_start = core.rfind(quote)
        first_end = core.find(quote)
        if first_end != -1 and last_start > first_end:
            core = core[first_end + 1 : last_start]
            break
    else:
        for sep in ("=", ":"):
            if sep in core:
                core = core.split(sep, 1)[1]
                break
        core = core.strip("\"' \t\n\r")
    return core


def _looks_like_false_positive(core_value: str) -> bool:
    if core_value.lower() in FALSE_POSITIVE_VALUES:
        return True

    if len(set(core_value)) <= 2:
        return True

    if core_value.lower().endswith(FALSE_POSITIVE_SUFFIXES):
        return True

    if MINIFIED_VAR_PATTERN.match(core_value):
        return True

    if re.fullmatch(r"[0-9]+", core_value):
        return True

    if _is_hex_string(core_value) and _shannon_entropy(core_value) < ENTROPY_THRESHOLD_HEX:
        return True

    if len(core_value) < 40 and _shannon_entropy(core_value) < ENTROPY_THRESHOLD_GENERIC:
        return True

    return False


def _redact(text: str) -> str:
    if len(text) > 16:
        return text[:8] + "..." + text[-4:]
    elif len(text) > 12:
        return text[:6] + "..." + text[-3:]
    return text[:6] + "..."


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class JSSecretScanner(ArtemisBase):
    identity = "js_secret_scanner"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    @staticmethod
    def _is_cdn_or_vendor(netloc: str, path: str) -> bool:
        netloc_lower = netloc.lower()
        for suffix in CDN_DOMAIN_SUFFIXES:
            if netloc_lower == suffix or netloc_lower.endswith("." + suffix):
                return True
        if VENDOR_PATH_PATTERNS.search(path.lower()):
            return True
        return False

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

        return chunk_urls[:MAX_WEBPACK_CHUNKS]

    def _fetch_js(self, js_url: str) -> Optional[str]:
        response = self.forgiving_http_get(js_url)
        if response is None:
            return None

        if response.status_code != 200:
            return None

        content_type = response.headers.get("Content-Type", "")
        if content_type and "html" in content_type.lower() and "javascript" not in content_type.lower():
            self.log.debug("Skipping %s: Content-Type is %s", js_url, content_type)
            return None

        content = response.content
        if not content or len(content) < 20:
            return None

        return content

    def _check_source_map(self, js_url: str, js_content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        map_match = SOURCEMAP_COMMENT_PATTERN.search(js_content)
        if map_match:
            map_ref = map_match.group(1)
            if map_ref.startswith("data:"):
                return findings
            map_url = urllib.parse.urljoin(js_url, map_ref)
        else:
            map_url = js_url + ".map"

        response = self.forgiving_http_get(map_url)
        if response is None:
            return findings

        content_type = response.headers.get("Content-Type", "")
        if response.status_code == 200 and (
            "json" in content_type or response.content.strip().startswith("{")
        ):
            findings.append(
                {
                    "pattern_name": "Exposed Source Map",
                    "severity": "medium",
                    "js_url": js_url,
                    "matched_text_redacted": _redact(map_url),
                    "match_start": map_match.start() if map_match else 0,
                }
            )

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
            findings.append(
                {
                    "pattern_name": "Internal URL Exposure",
                    "severity": "medium",
                    "js_url": js_url,
                    "matched_text_redacted": _redact(matched_url),
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

                core_value = _extract_core_value(matched_text)

                if _looks_like_false_positive(core_value):
                    continue

                dedup_key = f"{pattern.name}:{core_value}"
                if dedup_key in global_seen:
                    continue
                global_seen.add(dedup_key)

                findings.append(
                    {
                        "pattern_name": pattern.name,
                        "severity": pattern.severity,
                        "js_url": js_url,
                        "matched_text_redacted": _redact(matched_text),
                        "match_start": match.start(),
                    }
                )

        return findings

    def _scan_content_all(self, label: str, content: str, global_seen: Set[str]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        findings.extend(self._scan_js_content(label, content, global_seen))
        findings.extend(self._detect_env_var_exposure(label, content, global_seen))
        findings.extend(self._detect_internal_urls(label, content, global_seen))
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
            findings.extend(self._scan_content_all(inline_label, script_content, global_seen))

        return findings

    def _scan_external_js(
        self, js_url: str, global_seen: Set[str], scanned_urls: Set[str]
    ) -> List[Dict[str, Any]]:
        if js_url in scanned_urls:
            return []
        scanned_urls.add(js_url)

        findings: List[Dict[str, Any]] = []

        js_content = self._fetch_js(js_url)
        if js_content is None:
            return []

        findings.extend(self._scan_content_all(js_url, js_content, global_seen))

        sourcemap_findings = self._check_source_map(js_url, js_content)
        for sf in sourcemap_findings:
            dedup_key = f"sourcemap:{sf['matched_text_redacted']}"
            if dedup_key not in global_seen:
                global_seen.add(dedup_key)
                findings.append(sf)

        chunk_urls = self._discover_webpack_chunks(js_url, js_content)
        for chunk_url in chunk_urls:
            if len(findings) >= MAX_FINDINGS_PER_TARGET:
                break
            chunk_findings = self._scan_external_js(chunk_url, global_seen, scanned_urls)
            findings.extend(chunk_findings)

        return findings

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        time_start = time.time()
        self.log.info("JS Secret Scanner checking %s", url)

        all_findings: List[Dict[str, Any]] = []
        global_seen: Set[str] = set()
        scanned_urls: Set[str] = set()

        try:
            response = self.http_get(url)
        except Exception:
            self.log.info("Failed to fetch %s, skipping JS secret scan", url)
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
        self.log.info("Found %d JS files to scan on %s", len(js_urls), url)

        for js_url in js_urls:
            if len(all_findings) >= MAX_FINDINGS_PER_TARGET:
                self.log.info("Reached max findings limit (%d), stopping scan", MAX_FINDINGS_PER_TARGET)
                break
            js_findings = self._scan_external_js(js_url, global_seen, scanned_urls)
            all_findings.extend(js_findings)

        all_findings = all_findings[:MAX_FINDINGS_PER_TARGET]

        elapsed = time.time() - time_start
        self.log.info(
            "JS Secret Scanner finished %s in %.02fs: %d JS files scanned, %d findings",
            url,
            elapsed,
            len(scanned_urls),
            len(all_findings),
        )

        if all_findings:
            pattern_names = sorted(set(f["pattern_name"] for f in all_findings))
            high_count = sum(1 for f in all_findings if f["severity"] == "high")
            status = TaskStatus.INTERESTING
            status_reason = (
                f"Found {len(all_findings)} secret(s) ({high_count} high severity): "
                + ", ".join(pattern_names)
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
                "scan_duration_seconds": round(elapsed, 2),
            },
        )


if __name__ == "__main__":
    JSSecretScanner().loop()
