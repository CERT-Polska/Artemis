from pathlib import Path
from typing import Any, Dict, List

from dns import rdatatype

from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class DanglingDnsReporter(Reporter):
    DANGLING_DNS_RECORD = ReportType("dangling_dns_record")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "dangling_dns_detector":
            return []

        if not isinstance(task_result["result"], list):
            return []

        result = []
        for item in task_result["result"]:
            if item["record"] in (rdatatype.A, rdatatype.CNAME):
                result.append(
                    Report(
                        top_level_target=get_top_level_target(task_result),
                        target=item["domain"],
                        report_type=DanglingDnsReporter.DANGLING_DNS_RECORD,
                        additional_data={
                            "message_en": item["message"],
                        },
                        timestamp=task_result["created_at"],
                    )
                )
        return result

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_dangling_dns_record.jinja2"), priority=10
            ),
        ]
