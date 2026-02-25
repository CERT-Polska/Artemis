from pathlib import Path
from typing import Any, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_target_url, get_top_level_target


class GraphQLScannerReporter(Reporter):
    GRAPHQL_INTROSPECTION_ENABLED = ReportType("graphql_introspection_enabled")
    GRAPHQL_DEBUG_INTERFACE_EXPOSED = ReportType("graphql_debug_interface_exposed")
    GRAPHQL_BATCH_QUERY_SUPPORTED = ReportType("graphql_batch_query_supported")
    GRAPHQL_FIELD_SUGGESTIONS_ENABLED = ReportType("graphql_field_suggestions_enabled")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "graphql_scanner":
            return []

        if not isinstance(task_result.get("result"), dict):
            return []

        if task_result.get("status") != "INTERESTING":
            return []

        result = task_result["result"]
        reports: List[Report] = []
        top_level_target = get_top_level_target(task_result)
        target = get_target_url(task_result)
        timestamp = task_result["created_at"]

        if "introspection" in result:
            reports.append(
                Report(
                    top_level_target=top_level_target,
                    target=target,
                    report_type=GraphQLScannerReporter.GRAPHQL_INTROSPECTION_ENABLED,
                    timestamp=timestamp,
                    additional_data={
                        "endpoint": result["introspection"]["endpoint"],
                        "num_types_exposed": result["introspection"]["num_types_exposed"],
                        "custom_types_sample": result["introspection"].get("custom_types_sample", []),
                    },
                )
            )

        if "debug_interface" in result:
            reports.append(
                Report(
                    top_level_target=top_level_target,
                    target=target,
                    report_type=GraphQLScannerReporter.GRAPHQL_DEBUG_INTERFACE_EXPOSED,
                    timestamp=timestamp,
                    additional_data={
                        "endpoint": result["debug_interface"]["endpoint"],
                        "interface_type": result["debug_interface"]["interface_type"],
                    },
                )
            )

        if "batch_queries" in result:
            reports.append(
                Report(
                    top_level_target=top_level_target,
                    target=target,
                    report_type=GraphQLScannerReporter.GRAPHQL_BATCH_QUERY_SUPPORTED,
                    timestamp=timestamp,
                    additional_data={
                        "endpoint": result["batch_queries"]["endpoint"],
                    },
                )
            )

        if "field_suggestions" in result:
            reports.append(
                Report(
                    top_level_target=top_level_target,
                    target=target,
                    report_type=GraphQLScannerReporter.GRAPHQL_FIELD_SUGGESTIONS_ENABLED,
                    timestamp=timestamp,
                    additional_data={
                        "endpoint": result["field_suggestions"]["endpoint"],
                        "suggestions_sample": result["field_suggestions"].get("suggestions_sample", []),
                    },
                )
            )

        return reports

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_graphql_misconfiguration.jinja2"), priority=5
            ),
        ]
