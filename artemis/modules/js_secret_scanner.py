#!/usr/bin/env python3
"""
Artemis module: JS Secret Scanner

Scans inline ``<script>`` blocks and same-origin linked JavaScript files on
the target's root page for leaked secrets (API keys, tokens, private keys, …).

Matched secrets are **always redacted** in the task result so that reports
can be safely shared without exposing sensitive material.

Related GitHub issue: https://github.com/CERT-Polska/Artemis/issues/2516
"""

import urllib.parse
from typing import Dict, List

from bs4 import BeautifulSoup
from karton.core import Task
from requests.exceptions import RequestException

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.modules.data.js_secrets import SECRET_PATTERNS
from artemis.task_utils import get_target_url

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# The minimum number of visible characters in a redacted secret.
# Secrets shorter than this are fully replaced to avoid leaking the value.
_MIN_REDACTABLE_LENGTH = 8

# How many characters to reveal at the start / end of a redacted secret.
_REDACT_PREFIX_LEN = 5
_REDACT_SUFFIX_LEN = 4


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class JSSecretScanner(ArtemisBase):
    """
    Scans inline and linked JavaScript files on the target's homepage for
    leaked secrets (e.g. AWS keys, GitHub tokens, Stripe keys, private keys).

    Only scripts served from the **same origin** are fetched and scanned in
    order to avoid downloading third-party CDN assets (which are outside the
    scope of the target being assessed).

    Detected secrets are redacted before being persisted so that reports
    remain safe to share.
    """

    identity = "js_secret_scanner"

    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _redact(secret: str) -> str:
        """Return a redacted version of *secret*.

        Short secrets (≤ ``_MIN_REDACTABLE_LENGTH`` characters) are fully
        replaced; longer ones keep a small prefix and suffix so that an
        operator can *recognise* the key without being able to *use* it.

        Examples::

            >>> JSSecretScanner._redact("AKIA1234567890ABCDEF")
            'AKIA1***REDACTED***CDEF'
            >>> JSSecretScanner._redact("short")
            '***REDACTED***'
        """
        if len(secret) <= _MIN_REDACTABLE_LENGTH:
            return "***REDACTED***"
        return f"{secret[:_REDACT_PREFIX_LEN]}***REDACTED***{secret[-_REDACT_SUFFIX_LEN:]}"

    def _collect_same_origin_script_urls(self, url: str, soup: BeautifulSoup) -> List[str]:
        """Return de-duplicated URLs of ``<script src=…>`` tags on the same origin.

        External scripts (different hostname) and fragment-only references are
        excluded.
        """
        url_parsed = urllib.parse.urlparse(url)
        urls: List[str] = []
        for script_tag in soup.find_all("script", src=True):
            src = script_tag["src"]
            absolute_url = urllib.parse.urljoin(url, src)
            parsed = urllib.parse.urlparse(absolute_url)

            # Only include scripts hosted on the exact same hostname to avoid
            # scanning external CDNs (e.g. cdnjs, unpkg, googleapis).
            if parsed.hostname == url_parsed.hostname:
                urls.append(absolute_url.split("#")[0])
        return list(set(urls))

    def _scan_content(
        self,
        content: str,
        location: str,
        results: List[Dict[str, str]],
    ) -> None:
        """Run all secret patterns against *content* and append hits to *results*.

        Duplicate entries (same type + location + redacted value) are silently
        dropped so that a pattern appearing multiple times in a minified bundle
        does not bloat the report.
        """
        for secret_pattern in SECRET_PATTERNS:
            for match in secret_pattern.pattern.finditer(content):
                # Prefer the first capturing group (the actual secret value)
                # when available; fall back to the full match otherwise.
                raw_value = match.group(1) if match.lastindex else match.group(0)
                redacted = self._redact(raw_value)

                # De-duplicate within the same scan location.
                is_duplicate = any(
                    entry["type"] == secret_pattern.name
                    and entry["location"] == location
                    and entry["redacted_secret"] == redacted
                    for entry in results
                )
                if not is_duplicate:
                    results.append(
                        {
                            "type": secret_pattern.name,
                            "location": location,
                            "redacted_secret": redacted,
                        }
                    )

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info("JS secret scanner running against %s", url)

        # Fetch the root page via the standard Artemis HTTP helper which
        # honours rate-limiting, custom user-agents, SSL quirks, etc.
        try:
            response = self.http_get(url)
        except RequestException as exc:
            self.log.warning("Could not fetch %s: %s", url, exc)
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.ERROR,
                status_reason=f"Could not fetch {url}: {exc}",
            )
            return

        soup = BeautifulSoup(response.content, "html.parser")
        secrets_found: List[Dict[str, str]] = []

        # --- 1. Inline scripts -------------------------------------------
        for script_tag in soup.find_all("script"):
            if script_tag.string:
                self._scan_content(
                    script_tag.string,
                    f"inline <script> on {url}",
                    secrets_found,
                )

        # --- 2. Same-origin linked scripts --------------------------------
        for js_url in self._collect_same_origin_script_urls(url, soup):
            try:
                js_response = self.http_get(js_url)
                self._scan_content(js_response.content, js_url, secrets_found)
            except RequestException:
                self.log.info("Failed to fetch linked script %s – skipping", js_url)

        # --- 3. Persist results -------------------------------------------
        if secrets_found:
            status = TaskStatus.INTERESTING
            status_reason = (
                f"Found {len(secrets_found)} potential leaked secret(s) in "
                f"JavaScript files: "
                + ", ".join(sorted(set(s["type"] for s in secrets_found)))
            )
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={"secrets_found": secrets_found},
        )


if __name__ == "__main__":
    JSSecretScanner().loop()
