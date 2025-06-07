from abc import ABC
from typing import Any, Callable, Dict, List, Tuple

from .asset import Asset
from .language import Language
from .normal_form import (
    NormalForm,
    get_domain_normal_form,
    get_domain_score,
    get_url_normal_form,
    get_url_score,
)
from .report import Report
from .report_type import ReportType
from .templating import ReportEmailTemplateFragment


class Reporter(ABC):
    """
    A Reporter is a class that extracts vulnerabilities from raw task results and creates Reports out of them.

    It also provides parts of e-mail messages to render a given report type.
    """

    @classmethod
    def get_report_types(cls) -> List[ReportType]:
        """Types of reports provided by this Reporter."""
        return [getattr(cls, name) for name in dir(cls) if isinstance(getattr(cls, name), ReportType)]

    @staticmethod
    def get_alerts(all_reports: List[Report]) -> List[str]:
        """This looks at the final reports list and returns messages to be shown to the person
        that exports the e-mails (e.g. potential false positives)."""
        return []

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        """A method that extracts vulnerability information and creates Reports."""
        return []

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        """Fragments of e-mail messages to render report types provided by this Reporter."""
        return []

    @classmethod
    def get_normal_form_rules(cls) -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """
        A normal form rule is a callable that converts a report into a form such that two similar
        reports (e.g. insecure wordpress version on example.com and www.example.com) share the form.

        The form is used for deduplication.
        """
        return {report_type: Reporter.default_normal_form_rule for report_type in cls.get_report_types()}

    @classmethod
    def get_scoring_rules(cls) -> Dict[ReportType, Callable[[Report], List[int]]]:
        """
        A scoring rule takes a report and returns a score - for reports with same normal form, the one with highest
        score will be reported.

        Scores are compared lexicographically.
        """
        return {report_type: Reporter.default_scoring_rule for report_type in cls.get_report_types()}

    @staticmethod
    def dict_to_tuple(d: Dict[str, Any]) -> Tuple[Any, ...]:
        result = []
        for key, value in d.items():
            if isinstance(value, dict):
                result.append((key, Reporter.dict_to_tuple(value)))
            elif isinstance(value, list):
                result.append((key, tuple(value)))
            else:
                result.append((key, value))
        return tuple(result)

    @staticmethod
    def default_scoring_rule(report: Report) -> List[int]:
        assert report.target_is_url() or report.target_is_domain()
        return [get_url_score(report.target) if report.target_is_url() else get_domain_score(report.target)]

    @staticmethod
    def default_normal_form_rule(report: Report) -> NormalForm:
        assert report.target_is_url() or report.target_is_domain()
        return Reporter.dict_to_tuple(
            {
                "type": report.report_type,
                "target": (
                    get_url_normal_form(report.target)
                    if report.target_is_url()
                    else get_domain_normal_form(report.target)
                ),
            }
        )

    @staticmethod
    def get_assets(task_result: Dict[str, Any]) -> List[Asset]:
        """A method that extracts information about detected assets. They may or may not be vulnerable."""
        return []
