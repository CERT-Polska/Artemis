#!/usr/bin/env python3
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

from karton.core import Task

from artemis import http_requests, load_risk_class
from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase

NVD_RESPONSE_MAX_BYTES = 5 * 1024 * 1024
NVD_CACHE_TTL_SECONDS = 24 * 60 * 60
# NVD's public API is frequently slow to first byte, so it needs a longer timeout than the
# default used for scanning targets directly.
NVD_REQUEST_TIMEOUT_SECONDS = 30
# A failed lookup (network error, non-200 or unparseable body) is cached under the CPE key
# with a short TTL, so a transient NVD outage is not re-queried by every task for the same
# technology while still letting a genuine lookup happen again once the outage clears.
NVD_FAILURE_CACHE_TTL_SECONDS = 5 * 60
NVD_FAILURE_MARKER = "lookup_failed"
# NVD paginates with startIndex/resultsPerPage and reports totalResults. A versioned cpeName
# query comfortably fits one page, so this cap is only here to stop a runaway result set from
# paging forever at ~5 requests / 30s.
NVD_MAX_PAGES = 10


# A CPE version slot must look like a real version. Wappalyzer reports the version
# separately from its static CPE template, so guarding against a stray value such as
# "latest" (or anything carrying a ":") keeps us from building a malformed CPE that
# NVD would silently match nothing for.
_CPE_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.\-+]*$")


def _fill_cpe_version(cpe: str, version: Optional[str]) -> str:
    """
    Wappalyzer keeps the version slot as ``*`` even when the version is known, so
    substitute the real version (slot 5 of a cpe:2.3 URI) before hitting the API.
    A version that doesn't look like one is left as the wildcard, which
    ``_has_concrete_version`` then rejects rather than sending junk to NVD.
    """
    if not version or not _CPE_VERSION_RE.match(version):
        return cpe
    parts = cpe.split(":")
    if len(parts) < 6:
        return cpe
    if parts[5] != "*":
        return cpe
    parts[5] = version
    return ":".join(parts)


def _has_concrete_version(cpe: str) -> bool:
    """
    Whether the cpe:2.3 URI carries a real version in slot 5.

    NVD's ``cpeName`` parameter rejects a wildcard version outright with HTTP 404 (verified
    against apache, wordpress and nginx), so such a CPE cannot be looked up at all - and we
    wouldn't want to anyway, since the only thing NVD could return is "every CVE ever filed for
    this product", which says nothing about the host we scanned.
    """
    parts = cpe.split(":")
    return len(parts) > 5 and parts[5] not in ("", "*", "-")


def _cpe_product_key(cpe: str) -> str:
    """Return the ``part:vendor:product`` portion of a cpe:2.3 URI (e.g. ``a:apache:http_server``)."""
    parts = cpe.split(":")
    if len(parts) < 5:
        return ""
    return ":".join(parts[2:5])


def _node_has_vulnerable_product(node: Dict[str, Any], product_key: str) -> bool:
    """
    Whether ``product_key`` appears as a ``vulnerable: true`` CPE in this node.
    A ``negate: true`` node matches the *absence* of its CPEs, so it never counts.
    """
    if node.get("negate"):
        return False
    for match in node.get("cpeMatch") or []:
        if not isinstance(match, dict) or not match.get("vulnerable"):
            continue
        if _cpe_product_key(str(match.get("criteria", ""))) == product_key:
            return True
    return False


def _node_names_vulnerable_component(node: Dict[str, Any]) -> bool:
    """Whether this node contributes a ``vulnerable: true`` CPE of any product at all."""
    if node.get("negate"):
        return False
    return any(isinstance(match, dict) and match.get("vulnerable") for match in node.get("cpeMatch") or [])


def _configuration_implicates_product(configuration: Dict[str, Any], product_key: str) -> bool:
    """
    Whether ``product_key`` is a vulnerable component of this single configuration.

    A configuration joins its sibling nodes with an ``operator``. Ignoring that operator is
    what made the earlier check too shallow: under ``AND`` the CVE only applies when *every*
    node holds, so a CVE requiring two distinct vulnerable components must not be reported
    when we have only detected one of them.

    Nodes carrying solely ``vulnerable: false`` CPEs are the "running on" platform rather
    than a component (in CVE-2021-44228 the vulnerable node is log4j and the ``AND``-ed
    sibling is the Cisco appliance it runs on). Those describe the environment, which we
    cannot observe from a web technology fingerprint, so they never block a match.
    """
    nodes = [node for node in configuration.get("nodes") or [] if isinstance(node, dict)]
    if not any(_node_has_vulnerable_product(node, product_key) for node in nodes):
        return False
    if configuration.get("operator") != "AND":
        return True
    return all(
        _node_has_vulnerable_product(node, product_key) for node in nodes if _node_names_vulnerable_component(node)
    )


def _is_product_vulnerable(cve: Dict[str, Any], product_key: str) -> bool:
    """
    Whether ``product_key`` is the *vulnerable* component in this CVE.

    NVD's ``cpeName`` query also matches CVEs where the product is only a
    ``vulnerable: false`` "running on" platform (e.g. an app running behind the
    detected server). Reporting those would produce many false positives, so we
    accept a CVE only when the product is a vulnerable component — honouring
    ``negate`` on both the configuration and the node, since a negated branch
    matches the *absence* of its CPEs, and the configuration's ``operator`` (see
    ``_configuration_implicates_product``).

    Sibling configurations are alternatives, so any one of them implicating the product is
    enough. Depth stops here on purpose: an API 2.0 node has exactly ``operator``, ``negate``
    and ``cpeMatch`` and cannot nest further, so there is no deeper tree to descend into.
    """
    for configuration in cve.get("configurations") or []:
        if not isinstance(configuration, dict) or configuration.get("negate"):
            continue
        if _configuration_implicates_product(configuration, product_key):
            return True
    return False


def _best_base_score(metric_entries: Any) -> Optional[float]:
    """
    Pick a CVSS base score from an NVD metric list.

    NVD can attach more than one score to a CVE — its own ``Primary`` score plus a
    CNA-supplied ``Secondary`` one — so taking the first entry is not necessarily the
    authoritative one. Prefer the ``Primary`` (NVD-provided) score, falling back to the
    highest available when there is no Primary.
    """
    if not isinstance(metric_entries, list):
        return None
    scored: List[Tuple[bool, float]] = []
    for entry in metric_entries:
        if not isinstance(entry, dict):
            continue
        score = (entry.get("cvssData") or {}).get("baseScore")
        if isinstance(score, (int, float)):
            scored.append((entry.get("type") == "Primary", float(score)))
    if not scored:
        return None
    primary_scores = [score for is_primary, score in scored if is_primary]
    if primary_scores:
        return max(primary_scores)
    return max(score for _, score in scored)


def _extract_cves(payload: Any, product_key: str = "") -> List[Dict[str, Any]]:
    """
    Pull a flat (id, description, cvss_score) view out of NVD's JSON shape.

    When ``product_key`` (``part:vendor:product``) is given, CVEs where that
    product is not the vulnerable component are dropped — see
    :func:`_is_product_vulnerable`.
    """
    if not isinstance(payload, dict):
        return []
    raw_vulns = payload.get("vulnerabilities")
    if not isinstance(raw_vulns, list):
        return []

    result: List[Dict[str, Any]] = []
    for entry in raw_vulns:
        if not isinstance(entry, dict):
            continue
        cve = entry.get("cve")
        if not isinstance(cve, dict):
            continue
        cve_id = cve.get("id")
        if not cve_id:
            continue

        if product_key and not _is_product_vulnerable(cve, product_key):
            continue

        description = ""
        for desc in cve.get("descriptions") or []:
            if isinstance(desc, dict) and desc.get("lang") == "en":
                description = str(desc.get("value", ""))
                break

        cvss_score: Optional[float] = None
        metrics = cve.get("metrics") or {}
        # Prefer v3.x so scores stay comparable with the CVSS v3 values other Artemis findings
        # already report, then v4 (some newer CVEs only publish v4), then v2 as a last resort.
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
            score = _best_base_score(metrics.get(key))
            if score is not None:
                cvss_score = score
                break

        result.append({"id": str(cve_id), "description": description, "cvss_score": cvss_score})
    return result


def _summarize_findings(findings: List[Dict[str, Any]]) -> str:
    """Build a human-readable status reason for one or more CVE findings."""
    if len(findings) == 1:
        finding = findings[0]
        version = finding.get("technology_version")
        suffix = f" {version}" if version else ""
        return f"{len(finding['cves'])} CVE(s) found for {finding.get('technology_name')}{suffix}"
    total = sum(len(finding["cves"]) for finding in findings)
    return f"{total} CVE(s) found across {len(findings)} technologies"


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class CveLookup(ArtemisBase):
    """Looks up known CVEs for detected web technologies against NVD."""

    identity = "cve_lookup"
    filters = [
        {"type": TaskType.WEBAPP.value},
    ]

    def _cache_failure(self, cpe: str) -> None:
        """
        Cache the failure as a dict (a success is cached as a list) so ``_query_nvd``
        skips re-querying NVD for this CPE until the short failure TTL expires.
        """
        self.cache.set(
            cpe,
            json.dumps({NVD_FAILURE_MARKER: True}).encode("utf-8"),
            timeout=NVD_FAILURE_CACHE_TTL_SECONDS,
        )

    def _query_nvd(self, cpe: str) -> Optional[List[Dict[str, Any]]]:
        # NVD is slow and rate-limited (~5 requests / 30s without a key), so we use http_requests
        # (per-second throttle + longer timeout) plus a shared Redis cache kept for
        # NVD_CACHE_TTL_SECONDS — not FallbackAPICache, which does not throttle. Returns the CVE
        # list on success ([] = genuinely none found), or None when the lookup itself failed
        # (network error, non-200 or unparseable body) so the caller can report that distinctly
        # instead of as a green "no CVEs found".
        cached = self.cache.get(cpe)
        if cached is not None:
            try:
                decoded = json.loads(cached.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                decoded = None
            if isinstance(decoded, dict) and decoded.get(NVD_FAILURE_MARKER):
                return None  # recently failed - don't re-hammer NVD until the short TTL expires
            if isinstance(decoded, list):
                return decoded
            # anything else: fall through to a fresh fetch

        product_key = _cpe_product_key(cpe)
        api_url = Config.Modules.CveLookup.CVE_LOOKUP_NVD_API_URL
        cves: List[Dict[str, Any]] = []
        start_index = 0
        for _ in range(NVD_MAX_PAGES):
            url = f"{api_url}?{urlencode({'cpeName': cpe, 'startIndex': start_index})}"
            try:
                response = http_requests.get(
                    url,
                    requests_per_second=Config.Modules.CveLookup.CVE_LOOKUP_NVD_REQUESTS_PER_SECOND,
                    max_size=NVD_RESPONSE_MAX_BYTES,
                    timeout=NVD_REQUEST_TIMEOUT_SECONDS,
                )
            except Exception as e:
                self.log.warning(f"NVD request failed for cpe={cpe} at startIndex={start_index}: {e}")
                self._cache_failure(cpe)
                return None

            if response.status_code != 200:
                self.log.warning(
                    f"NVD returned status {response.status_code} for cpe={cpe} at startIndex={start_index}"
                )
                self._cache_failure(cpe)
                return None

            try:
                payload = response.json()
            except ValueError:
                self.log.warning(f"NVD returned non-JSON for cpe={cpe} at startIndex={start_index}")
                self._cache_failure(cpe)
                return None

            cves.extend(_extract_cves(payload, product_key))

            # Advance by what NVD says it served, not by what survived filtering, otherwise a
            # page whose CVEs were all filtered out would make us re-request the same offset.
            total_results = payload.get("totalResults")
            results_per_page = payload.get("resultsPerPage")
            if not isinstance(total_results, int) or not isinstance(results_per_page, int) or results_per_page <= 0:
                break
            start_index += results_per_page
            if start_index >= total_results:
                break
        else:
            self.log.warning(f"NVD results for cpe={cpe} exceeded {NVD_MAX_PAGES} pages, truncating")

        self.cache.set(cpe, json.dumps(cves).encode("utf-8"), timeout=NVD_CACHE_TTL_SECONDS)
        return cves

    def run(self, current_task: Task) -> None:
        url = current_task.get_payload("url")
        technologies = current_task.get_payload("technologies") or []

        findings: List[Dict[str, Any]] = []
        lookup_failed = False
        for technology in technologies:
            if not isinstance(technology, dict):
                continue
            cpe = technology.get("cpe")
            if not cpe:
                continue

            technology_version = technology.get("version")
            normalized_cpe = _fill_cpe_version(cpe, technology_version)
            if not _has_concrete_version(normalized_cpe):
                # No usable version - NVD answers a wildcard cpeName with 404, and "some release
                # of this product has a CVE" says nothing about this host, so skip the lookup.
                continue
            cves = self._query_nvd(normalized_cpe)
            if cves is None:
                # The NVD lookup itself failed - remember it so we don't report a
                # green "no CVEs found" when nothing was actually checked.
                lookup_failed = True
                continue
            if not cves:
                continue

            findings.append(
                {
                    "technology_name": technology.get("name"),
                    "technology_version": technology_version,
                    "cpe": normalized_cpe,
                    "cves": cves,
                }
            )

        if findings:
            status = TaskStatus.INTERESTING
            status_reason = _summarize_findings(findings)
        elif lookup_failed:
            status = TaskStatus.ERROR
            status_reason = "NVD lookup failed for one or more detected technologies"
        else:
            status = TaskStatus.OK
            status_reason = "no CVEs found for detected technologies"

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={"url": url, "findings": findings},
        )


if __name__ == "__main__":
    # Single process on purpose: the per-second NVD throttle in _query_nvd is per-process, so
    # cve_lookup must not be scaled to multiple workers (parallel_loop) or their combined request
    # rate would exceed NVD's limit. Scaling would need a shared/distributed rate limit instead.
    CveLookup().loop()
