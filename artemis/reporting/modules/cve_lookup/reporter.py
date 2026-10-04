from pathlib import Path
from typing import Any, Callable, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import NormalForm, get_url_normal_form
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class CveLookupReporter(Reporter):
    TECHNOLOGY_CVE_FOUND = ReportType("technology_cve_found")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "cve_lookup":
            return []

        if task_result["status"] != "INTERESTING":
            return []

        result_data = task_result["result"]
        if not isinstance(result_data, dict):
            return []

        url = result_data.get("url")
        findings = result_data.get("findings") or []
        if not url or not findings:
            return []

        reports = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            cves = finding.get("cves") or []
            if not cves:
                continue
            reports.append(
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=url,
                    report_type=CveLookupReporter.TECHNOLOGY_CVE_FOUND,
                    additional_data={
                        "technology_name": finding.get("technology_name"),
                        "technology_version": finding.get("technology_version"),
                        "cpe": finding.get("cpe"),
                        "cves": cves,
                        "max_cvss": _max_cvss(cves),
                    },
                    timestamp=task_result["created_at"],
                )
            )
        return reports

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_technology_cve_found.jinja2"), priority=4
            ),
        ]

    @classmethod
    def get_normal_form_rules(cls) -> Dict[ReportType, Callable[[Report], NormalForm]]:
        def rule(report: Report) -> NormalForm:
            return Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_url_normal_form(report.target),
                    "technology_name": report.additional_data.get("technology_name"),
                    "technology_version": report.additional_data.get("technology_version"),
                }
            )

        return {report_type: rule for report_type in cls.get_report_types()}


def _max_cvss(cves: List[Dict[str, Any]]) -> float:
    scores = [c.get("cvss_score") for c in cves if isinstance(c, dict)]
    return max((s for s in scores if isinstance(s, (int, float))), default=0.0)
