#!/usr/bin/env python3
"""
JsVulnDetector – Artemis module that detects vulnerable client-side JavaScript
libraries using the Retire.js vulnerability database.

Scope: only external scripts referenced via ``<script src="...">``.  Inline
scripts are intentionally excluded to keep the module fast and avoid false
positives from minified/transpiled bundles.

Per-page limits
---------------
* At most ``MAX_SCRIPTS_PER_PAGE`` script sources are inspected.
* Script content is fetched (to attempt version extraction) only when the URL
  itself does not reveal the version.  The fetched content is truncated to
  ``MAX_SCRIPT_CONTENT_BYTES`` to protect against very large bundles.
"""
import json
import re
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import bs4
from karton.core import Task
from packaging.version import InvalidVersion, Version

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url

# --------------------------------------------------------------------------- #
#  Tunables
# --------------------------------------------------------------------------- #

MAX_SCRIPTS_PER_PAGE = 25
MAX_SCRIPT_CONTENT_BYTES = 256 * 1024  # 256 KB

DB_PATH = Path(__file__).parent / "data" / "jsrepository.json"


# --------------------------------------------------------------------------- #
#  Database helpers
# --------------------------------------------------------------------------- #


def _load_db() -> Dict[str, Any]:
    with open(DB_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _extract_version(text: str, patterns: List[str]) -> Optional[str]:
    """Return the first capturing group matched by any pattern, or *None*."""
    for raw_pattern in patterns:
        try:
            match = re.search(raw_pattern, text, re.IGNORECASE)
        except re.error:
            continue
        if match:
            groups = match.groups()
            if groups and groups[0]:
                return groups[0].strip()
    return None


def _version_is_vulnerable(version_str: str, vuln_entry: Dict[str, Any]) -> bool:
    """
    Return *True* when *version_str* falls within the affected range described
    by *vuln_entry*, which may contain ``"atOrAbove"`` and/or ``"below"`` keys.
    """
    try:
        version = Version(version_str)
    except InvalidVersion:
        # Non-PEP-440 version string – we cannot compare it safely.
        return False

    at_or_above = vuln_entry.get("atOrAbove")
    below = vuln_entry.get("below")

    if at_or_above:
        try:
            if version < Version(at_or_above):
                return False
        except InvalidVersion:
            return False

    if below:
        try:
            if version >= Version(below):
                return False
        except InvalidVersion:
            return False

    return True


def _SEVERITY_RANK(s: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s.lower(), 0)


def check_library(
    lib_name: str,
    lib_info: Dict[str, Any],
    script_url: str,
    script_content: Optional[str],
) -> Optional[Dict[str, Any]]:
    """
    Try to detect *lib_name* in the given script and, if a known-vulnerable
    version is found, return a finding dictionary.  Returns *None* when no
    vulnerability is detected.

    The URL path (``script_url``) is always tried first so that fetching the
    script content can be skipped for the common case where the version appears
    in the file name.
    """
    extractors = lib_info.get("extractors", {})

    # 1. Try URL / filename patterns (no extra HTTP request).
    detected_version: Optional[str] = None
    for key in ("filename", "uri"):
        detected_version = _extract_version(script_url, extractors.get(key, []))
        if detected_version:
            break

    # 2. Fall back to file-content patterns when needed.
    if not detected_version and script_content is not None:
        detected_version = _extract_version(script_content, extractors.get("filecontent", []))

    if not detected_version:
        return None

    # 3. Check detected version against every vulnerability entry.
    matching: List[Dict[str, Any]] = [
        v for v in lib_info.get("vulnerabilities", []) if _version_is_vulnerable(detected_version, v)
    ]
    if not matching:
        return None

    cves: List[str] = []
    severities: List[str] = []
    info_urls: List[str] = []
    for vuln in matching:
        ids = vuln.get("identifiers", {})
        cves.extend(ids.get("CVE", []))
        severities.append(vuln.get("severity", "unknown"))
        info_urls.extend(vuln.get("info", []))

    worst_severity = max(severities, key=_SEVERITY_RANK) if severities else "unknown"

    return {
        "library": lib_name,
        "detected_version": detected_version,
        "script_url": script_url,
        "cves": sorted(set(cves)),
        "severity": worst_severity,
        "info_urls": list(dict.fromkeys(info_urls)),  # deduplicated, preserving order
    }


# --------------------------------------------------------------------------- #
#  Module class
# --------------------------------------------------------------------------- #


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class JsVulnDetector(ArtemisBase):
    """
    Detects vulnerable client-side JavaScript libraries (e.g. jQuery, Bootstrap,
    Lodash) loaded via ``<script src="...">``, using the Retire.js vulnerability
    database bundled at ``artemis/modules/data/jsrepository.json``.

    For each detected library, the module reports the library name, the detected
    version, associated CVE identifiers, the script URL, and remediation guidance
    (upgrade to the latest stable release).
    """

    identity = "js_vuln_detector"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._db: Dict[str, Any] = _load_db()

    # ---------------------------------------------------------------------- #
    #  Internal helpers
    # ---------------------------------------------------------------------- #

    def _fetch_script(self, script_url: str) -> Optional[str]:
        """
        Fetch *script_url* and return its decoded text content, or *None* on
        any error (connection failure, non-200 status, binary content, …).
        Content larger than ``MAX_SCRIPT_CONTENT_BYTES`` is ignored.
        """
        try:
            response = self.forgiving_http_get(script_url, max_size=MAX_SCRIPT_CONTENT_BYTES)
            if response is None:
                return None
            if response.status_code != 200:
                return None
            content_type = response.headers.get("content-type", "")
            # Accept application/javascript, text/javascript, text/plain, etc.
            if "html" in content_type.lower():
                return None
            return response.content
        except Exception as exc:
            self.log.debug("Could not fetch script %s: %s", script_url, exc)
            return None

    # ---------------------------------------------------------------------- #
    #  Karton task handler
    # ---------------------------------------------------------------------- #

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)

        # Fetch the target page -------------------------------------------- #
        try:
            page_response = self.http_get(url)
        except Exception as exc:
            self.log.error("Failed to fetch %s: %s", url, exc)
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.ERROR,
                status_reason=str(exc),
                data={"findings": [], "scripts_checked": 0},
            )
            return

        if page_response.status_code != 200:
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.OK,
                status_reason=None,
                data={"findings": [], "scripts_checked": 0},
            )
            return

        content_type = page_response.headers.get("content-type", "")
        if "html" not in content_type.lower():
            # Not an HTML page – nothing to scan.
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.OK,
                status_reason=None,
                data={"findings": [], "scripts_checked": 0},
            )
            return

        # Parse HTML and extract <script src="…"> --------------------------- #
        soup = bs4.BeautifulSoup(page_response.content_bytes, "html.parser")
        script_tags = soup.find_all("script", src=True)

        findings: List[Dict[str, Any]] = []
        scripts_checked = 0

        for tag in script_tags[:MAX_SCRIPTS_PER_PAGE]:
            src: str = (tag.get("src") or "").strip()
            if not src:
                continue

            script_url = urllib.parse.urljoin(url, src)
            # Use only the URL path for pattern matching (avoids false positives
            # from query-string parameters).
            url_path = urllib.parse.urlparse(script_url).path.lower()

            # Lazily fetched script content (at most once per script).
            script_content: Optional[str] = None
            content_fetched = False
            scripts_checked += 1

            for lib_name, lib_info in self._db.items():
                # Quick pre-check: does the URL path look related to this lib?
                # We try URL-only first to avoid an unnecessary HTTP request.
                finding = check_library(lib_name, lib_info, url_path, script_content)

                if finding is None and not content_fetched:
                    # Fetch the script content and retry.
                    script_content = self._fetch_script(script_url)
                    content_fetched = True
                    finding = check_library(lib_name, lib_info, url_path, script_content)

                if finding is not None:
                    # Record the full resolved URL for reporting.
                    finding["script_url"] = script_url
                    findings.append(finding)
                    # One library per script is the common case; keep scanning
                    # others in case multiple libs are bundled.

        # Build result ------------------------------------------------------- #
        if findings:
            messages = []
            for f in findings:
                cve_str = ", ".join(f["cves"]) if f["cves"] else "no CVE listed"
                messages.append(
                    f"{f['library']} {f['detected_version']} "
                    f"loaded from {f['script_url']} is vulnerable ({cve_str}). "
                    f"Please upgrade to the latest stable version."
                )
            status = TaskStatus.INTERESTING
            status_reason = "; ".join(messages)
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={"findings": findings, "scripts_checked": scripts_checked},
        )


if __name__ == "__main__":
    JsVulnDetector().loop()
