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


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class JSSecretScanner(ArtemisBase):
    """
    Scans JavaScript files for hardcoded secrets such as API keys, tokens, and credentials.
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

            # Strip query string and fragment for deduplication
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

    def _scan_js_content(self, js_url: str, content: str, global_seen: Set[str]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for pattern in SECRET_PATTERNS:
            for match in pattern.regex.finditer(content):
                matched_text = match.group(0).strip()

                if len(matched_text) < MIN_SECRET_LENGTH:
                    continue

                # Extract the innermost quoted value if present, otherwise strip outer quotes
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

        return findings

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"JS Secret Scanner checking {url}")

        all_findings: List[Dict[str, Any]] = []
        global_seen: Set[str] = set()

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

            try:
                js_response = self.http_get(js_url)
                js_content = js_response.content

                if not js_content:
                    continue

                # Skip responses that are clearly not JavaScript (e.g., HTML error pages)
                content_type = js_response.headers.get("Content-Type", "")
                if content_type and "html" in content_type.lower() and "javascript" not in content_type.lower():
                    self.log.debug(f"Skipping {js_url}: Content-Type is {content_type}")
                    continue

                file_findings = self._scan_js_content(js_url, js_content, global_seen)
                all_findings.extend(file_findings)
            except Exception:
                self.log.debug(f"Failed to fetch JS file: {js_url}")
                continue

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
                "js_files_scanned": len(js_urls),
                "inline_scripts_scanned": True,
            },
        )


if __name__ == "__main__":
    JSSecretScanner().loop()
