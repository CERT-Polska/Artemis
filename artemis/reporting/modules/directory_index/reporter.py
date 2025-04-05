import os
import urllib.parse
from typing import Any, Callable, Dict, List

from artemis.models import FoundURL
from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import (
    NormalForm,
    get_url_normal_form,
    get_url_score,
)
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import add_port_to_url, get_top_level_target


class DirectoryIndexReporter(Reporter):
    DIRECTORY_INDEX = ReportType("directory_index")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        reports = []
        if task_result["headers"]["receiver"] == "bruter":
            if not isinstance(task_result["result"], dict):
                return []

            for found_url_dict in task_result["result"].get("found_urls", {}):
                found_url = FoundURL(**found_url_dict)

                if found_url.has_directory_index:
                    reports.append(DirectoryIndexReporter._build_directory_index_report(task_result, found_url))
        elif task_result["headers"]["receiver"] == "robots":
            if not isinstance(task_result["result"], dict):
                return []

            for found_url_dict in task_result["result"].get("result", {}).get("found_urls", {}):
                found_url = FoundURL(**found_url_dict)

                assert found_url.has_directory_index

                reports.append(DirectoryIndexReporter._build_directory_index_report(task_result, found_url))
        elif task_result["headers"]["receiver"] == "directory_index":
            if not isinstance(task_result["result"], list):
                return []

            for found_url_dict in task_result["result"]:
                found_url = FoundURL(**found_url_dict)

                assert found_url.has_directory_index

                reports.append(DirectoryIndexReporter._build_directory_index_report(task_result, found_url))

        return reports

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_directory_index.jinja2"), priority=4
            ),
        ]

    @staticmethod
    def get_scoring_rules() -> Dict[ReportType, Callable[[Report], List[int]]]:
        """See the docstring in the parent class."""
        return {
            DirectoryIndexReporter.DIRECTORY_INDEX: lambda report: [
                report.additional_data["score"],
                -len(report.target),
                get_url_score(report.target),
            ]
        }

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {
            DirectoryIndexReporter.DIRECTORY_INDEX: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_url_normal_form(DirectoryIndexReporter._strip_path(report.target)),
                }
            )
        }

    @staticmethod
    def _build_directory_index_report(task_result: Dict[str, Any], found_url: FoundURL) -> Report:
        found_url_parsed = urllib.parse.urlparse(found_url.url)

        path_prefix_scores = {
            "/file": 2,
            "/pliki": 2,
            "/backup": 2,
            "/upload": 2,
            "/wp-content/uploads": 2,
            "/temp": 1,
            "/tmp": 1,
            "/css": -1,
            "/js": -1,
            "/assets": -1,
            "/pub": -1,
        }

        if found_url_parsed.path == "/backup/" and "backup.class.php" in found_url.content_prefix:
            score = -1  # /backup/ folder in Moodle is a false positive
        else:
            score = 0
            for path_prefix, score_for_path_prefix in path_prefix_scores.items():
                if found_url_parsed.path.startswith(path_prefix):
                    score = score_for_path_prefix

        return Report(
            top_level_target=get_top_level_target(task_result),
            target=add_port_to_url(f"{found_url_parsed.scheme}://{found_url_parsed.netloc}{found_url_parsed.path}"),
            report_type=ReportType("directory_index"),
            additional_data={"score": score},
            timestamp=task_result["created_at"],
        )

    @staticmethod
    def _strip_path(url: str) -> str:
        url_parsed = urllib.parse.urlparse(url)
        url_parsed_dict = url_parsed._asdict()
        url_parsed_dict["path"] = ""
        return urllib.parse.urlunparse(urllib.parse.ParseResult(**url_parsed_dict))
