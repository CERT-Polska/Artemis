import os
import urllib.parse
from typing import Any, Callable, Dict, List

from artemis.modules.lfi_detector import LFIFindings
from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import NormalForm, get_domain_normal_form
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_target_url, get_top_level_target


class LFIDetectorReporter(Reporter):
    LFI = ReportType("lfi_vulnerability")
    RCE = ReportType("rce_vulnerability")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "lfi_detector":
            return []

        if not task_result["status"] == "INTERESTING":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        lfi_data = []
        rce_data = []
        for item in task_result["result"]["result"]:
            if item.get("code") == LFIFindings.LFI_VULNERABILITY.value:
                lfi_data.append(item)
            elif item.get("code") == LFIFindings.RCE_VULNERABILITY.value:
                rce_data.append(item)
            else:
                raise ValueError("Not implemented LFIFinding")
        return [
            Report(
                top_level_target=get_top_level_target(task_result),
                target=get_target_url(task_result),
                report_type=LFIDetectorReporter.LFI,
                additional_data={"result": lfi_data, "statements": task_result["result"]["statements"]},
                timestamp=task_result["created_at"],
            ),
            Report(
                top_level_target=get_top_level_target(task_result),
                target=get_target_url(task_result),
                report_type=LFIDetectorReporter.RCE,
                additional_data={"result": rce_data, "statements": task_result["result"]["statements"]},
                timestamp=task_result["created_at"],
            ),
        ]

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_lfi.jinja2"),
                priority=8,
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_rce.jinja2"),
                priority=8,
            ),
        ]

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {
            LFIDetectorReporter.LFI: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_domain_normal_form(urllib.parse.urlparse(report.target).hostname or ""),
                }
            ),
            LFIDetectorReporter.RCE: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_domain_normal_form(urllib.parse.urlparse(report.target).hostname or ""),
                }
            ),
        }
