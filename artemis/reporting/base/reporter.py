from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Tuple

from .language import Language
from .normal_form import NormalForm, get_url_normal_form, get_url_score
from .report import Report
from .report_type import ReportType
from .templating import ReportEmailTemplateFragment


class Reporter(ABC):
    """
    A Reporter is a class that extracts vulnerabilities from raw task results and creates Reports out of them.

    It also provides parts of e-mail messages to render a given report type.
    """

    @staticmethod
    @abstractmethod
    def get_report_types() -> List[ReportType]:
        """Types of reports provided by this Reporter."""
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        """A method that extracts vulnerability information and creates Reports."""
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        """Fragments of e-mail messages to render report types provided by this Reporter."""
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """
        A normal form rule is a callable that converts a report into a form such that two similar
        reports (e.g. insecure wordpress version on example.com and www.example.com) share the form.

        The form is used for deduplication.
        """
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def get_scoring_rules() -> Dict[ReportType, Callable[[Report], List[int]]]:
        """
        A scoring rule takes a report and returns a score - for reports with same normal form, the one with highest
        score will be reported.

        Scores are compared lexicographically.
        """

    @staticmethod
    def dict_to_tuple(d: Dict[str, str]) -> Tuple[Tuple[str, str], ...]:
        return tuple(d.items())

    @staticmethod
    def default_scoring_rule(report: Report) -> List[int]:
        return [get_url_score(report.target)]

    @staticmethod
    def default_normal_form_rule(report: Report) -> NormalForm:
        return Reporter.dict_to_tuple(
            {
                "type": report.report_type,
                "target": get_url_normal_form(report.target),
            }
        )
