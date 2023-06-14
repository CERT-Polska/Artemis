import os
from typing import Any, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target
from artemis.utils import is_ip_address


class PortScannerReporter(Reporter):
    OPEN_PORT_REMOTE_DESKTOP = ReportType("open_port_remote_desktop")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "port_scanner":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        result = []
        for ip, data in task_result["result"].items():
            assert is_ip_address(ip)

            for port, port_data in data.items():
                if port_data["service"] in ["rdp", "VNC"]:
                    if int(port) == 111:
                        continue  # RDPs on this port are false positives

                    result.append(
                        Report(
                            top_level_target=get_top_level_target(task_result),
                            target=f"{port_data['service'].lower()}://{ip}:{port}",
                            report_type=PortScannerReporter.OPEN_PORT_REMOTE_DESKTOP,
                            additional_data={
                                "port": port,
                                "service": port_data["service"],
                            },
                            timestamp=task_result["created_at"],
                        )
                    )
        return result

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_open_port_remote_desktop.jinja2"), priority=3
            ),
        ]
