import os
from typing import Any, Dict, List

from artemis.ip_utils import is_ip_address
from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class PortScannerReporter(Reporter):
    OPEN_PORT_REMOTE_DESKTOP = ReportType("open_port_remote_desktop")
    OPEN_PORT_DATABASE = ReportType("open_port_database")
    OPEN_PORT_SMB = ReportType("open_port_smb")

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
                service = port_data["service"].lower()
                if service in ["mysql", "postgresql", "mssql"]:
                    result.append(
                        Report(
                            top_level_target=get_top_level_target(task_result),
                            target=f"{service}://{ip}:{port}",
                            report_type=PortScannerReporter.OPEN_PORT_DATABASE,
                            additional_data={
                                "port": port,
                                "service": service,
                            },
                            timestamp=task_result["created_at"],
                        )
                    )
                if service in ["smb"]:
                    result.append(
                        Report(
                            top_level_target=get_top_level_target(task_result),
                            target=f"{service}://{ip}:{port}",
                            report_type=PortScannerReporter.OPEN_PORT_SMB,
                            additional_data={
                                "port": port,
                                "service": service,
                            },
                            timestamp=task_result["created_at"],
                        )
                    )
                if service in ["rdp", "vnc"]:
                    if int(port) == 111:
                        continue  # RDPs on this port are false positives

                    result.append(
                        Report(
                            top_level_target=get_top_level_target(task_result),
                            target=f"{service}://{ip}:{port}",
                            report_type=PortScannerReporter.OPEN_PORT_REMOTE_DESKTOP,
                            additional_data={
                                "port": port,
                                "service": service,
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
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_open_port_smb.jinja2"), priority=2
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_open_port_database.jinja2"), priority=1
            ),
        ]
