#!/usr/bin/env python3
import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from karton.core import Task

from artemis import http_requests, load_risk_class
from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RESPONSE_MAX_BYTES = 5 * 1024 * 1024
NVD_CACHE_TTL_SECONDS = 24 * 60 * 60
# NVD's public API is frequently slow to first byte, so it needs a longer timeout than the
# default used for scanning targets directly.
NVD_REQUEST_TIMEOUT_SECONDS = 30


def _fill_cpe_version(cpe: str, version: Optional[str]) -> str:
    """
    Wappalyzer keeps the version slot as ``*`` even when the version is known.
    Querying NVD with a wildcard version returns every CVE for every release
    of the product, so substitute the real version (slot 5 of a cpe:2.3 URI)
    before hitting the API.
    """
    if not version:
        return cpe
    parts = cpe.split(":")
    if len(parts) < 6:
        return cpe
    if parts[5] != "*":
        return cpe
    parts[5] = version
    return ":".join(parts)


def _cpe_product_key(cpe: str) -> str:
    """Return the ``part:vendor:product`` portion of a cpe:2.3 URI (e.g. ``a:apache:http_server``)."""
    parts = cpe.split(":")
    if len(parts) < 5:
        return ""
    return ":".join(parts[2:5])


def _is_product_vulnerable(cve: Dict[str, Any], product_key: str) -> bool:
    """
    Whether ``product_key`` is the *vulnerable* component in this CVE.

    NVD's ``cpeName`` query also returns CVEs where the product is only a
    ``vulnerable: false`` "running on" platform for some other product's
    vulnerability (e.g. a third-party Apache module, or an application that
    happens to run behind the detected server). Reporting those as
    vulnerabilities of the detected technology produces large numbers of false
    positives, so we keep a CVE only when our product appears with
    ``vulnerable: true``.
    """
    for configuration in cve.get("configurations") or []:
        if not isinstance(configuration, dict):
            continue
        for node in configuration.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch") or []:
                if not isinstance(match, dict) or not match.get("vulnerable"):
                    continue
                if _cpe_product_key(str(match.get("criteria", ""))) == product_key:
                    return True
    return False


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
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_entries = metrics.get(key)
            if isinstance(metric_entries, list) and metric_entries:
                first = metric_entries[0]
                if isinstance(first, dict):
                    data = first.get("cvssData") or {}
                    score = data.get("baseScore")
                    if isinstance(score, (int, float)):
                        cvss_score = float(score)
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

    def _query_nvd(self, cpe: str) -> List[Dict[str, Any]]:
        # NVD is a slow, rate-limited public API (~5 requests / 30s without a key). We deliberately
        # use http_requests + a Redis cache here rather than FallbackAPICache (which backs the
        # github/wordpress.org lookups): FallbackAPICache does not throttle requests, while
        # http_requests has the built-in per-second throttle we need to stay under NVD's rate limit,
        # and a longer request timeout (NVD's first byte can take well over the default). The Redis
        # cache is shared across workers and kept for NVD_CACHE_TTL_SECONDS, matching NVD's
        # slow-changing CVE data.
        cached = self.cache.get(cpe)
        if cached is not None:
            try:
                decoded = json.loads(cached.decode("utf-8"))
                if isinstance(decoded, list):
                    return decoded
            except (ValueError, UnicodeDecodeError):
                pass  # fall through to a fresh fetch

        url = f"{NVD_API_URL}?{urlencode({'cpeName': cpe})}"
        try:
            response = http_requests.get(
                url,
                requests_per_second=Config.Modules.CveLookup.CVE_LOOKUP_NVD_REQUESTS_PER_SECOND,
                max_size=NVD_RESPONSE_MAX_BYTES,
                timeout=NVD_REQUEST_TIMEOUT_SECONDS,
            )
        except Exception as e:
            self.log.warning(f"NVD request failed for cpe={cpe}: {e}")
            return []

        if response.status_code != 200:
            self.log.warning(f"NVD returned status {response.status_code} for cpe={cpe}")
            return []

        try:
            payload = response.json()
        except ValueError:
            self.log.warning(f"NVD returned non-JSON for cpe={cpe}")
            return []

        cves = _extract_cves(payload, _cpe_product_key(cpe))
        self.cache.set(cpe, json.dumps(cves).encode("utf-8"), timeout=NVD_CACHE_TTL_SECONDS)
        return cves

    def run(self, current_task: Task) -> None:
        url = current_task.get_payload("url")
        technologies = current_task.get_payload("technologies") or []

        findings: List[Dict[str, Any]] = []
        for technology in technologies:
            if not isinstance(technology, dict):
                continue
            cpe = technology.get("cpe")
            if not cpe:
                continue

            technology_version = technology.get("version")
            normalized_cpe = _fill_cpe_version(cpe, technology_version)
            cves = self._query_nvd(normalized_cpe)
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
    CveLookup.parallel_loop()
