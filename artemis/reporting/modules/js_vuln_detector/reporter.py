from pathlib import Path
from typing import Any, Callable, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import NormalForm, get_url_normal_form
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_target_url, get_top_level_target


class JsVulnDetectorReporter(Reporter):
    VULNERABLE_JS_LIBRARY = ReportType("vulnerable_js_library")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "js_vuln_detector":
            return []

        if not isinstance(task_result.get("result"), dict):
            return []

        findings = task_result["result"].get("findings", [])
        if not findings:
            return []

        return [
            Report(
                top_level_target=get_top_level_target(task_result),
                target=get_target_url(task_result),
                report_type=JsVulnDetectorReporter.VULNERABLE_JS_LIBRARY,
                additional_data={"findings": findings},
                timestamp=task_result["created_at"],
            )
        ]

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_vulnerable_js_library.jinja2"),
                priority=3,
            ),
        ]

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """Two reports for the same URL with the same set of vulnerable libraries share a normal form."""
        return {
            JsVulnDetectorReporter.VULNERABLE_JS_LIBRARY: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_url_normal_form(report.target),
                    "findings": tuple(
                        Reporter.dict_to_tuple(
                            {
                                "library": f["library"],
                                "detected_version": f["detected_version"],
                                "cves": tuple(sorted(f.get("cves", []))),
                            }
                        )
                        for f in sorted(
                            report.additional_data["findings"],
                            key=lambda x: (x["library"], x["detected_version"]),
                        )
                    ),
                }
            )
        }
