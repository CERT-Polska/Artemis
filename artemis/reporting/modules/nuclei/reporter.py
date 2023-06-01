import os
import urllib.parse
from typing import Any, Callable, Dict, List

from artemis.config import Config
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
from artemis.reporting.exceptions import TranslationNotFoundException
from artemis.reporting.utils import (
    add_protocol_if_needed,
    get_target,
    get_top_level_target,
)
from artemis.utils import get_host_from_url

from .translations.nuclei_messages import pl_PL as translations_nuclei_messages_pl_PL


class NucleiReporter(Reporter):
    NUCLEI_VULNERABILITY = ReportType("nuclei_vulnerability")

    @staticmethod
    def get_report_types() -> List[ReportType]:
        return [NucleiReporter.NUCLEI_VULNERABILITY]

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        def _is_url_without_path_query_fragment(url: str) -> bool:
            url_parsed = urllib.parse.urlparse(url)
            return url_parsed.path.strip("/") == "" and not url_parsed.query and not url_parsed.fragment

        if task_result["headers"]["receiver"] != "nuclei":
            return []

        if not isinstance(task_result["result"], list):
            return []

        result = []

        for vulnerability in task_result["result"]:
            if not isinstance(vulnerability, dict):
                continue

            if vulnerability["info"]["severity"] in ["high", "critical"]:
                if vulnerability["template"] in Config.NUCLEI_TEMPLATES_TO_SKIP:
                    continue

                if "description" in vulnerability["info"]:
                    description = vulnerability["info"]["description"]
                else:
                    description = "[no description] " + vulnerability["template"]

                target = get_target(task_result)

                # Sometimes matched_at differs from the target: has the same host, but different port. This happens e.g.
                # when an unsecured Redis instance has been found (in that case, the port is 6379).
                #
                # In such cases, we want the target to be the actual port the problem has been found on, not a random one.
                #
                # We want to restrict this behavior only to services on empty path (e.g. redis://some-domain:6379) because
                # if the path is nonempty, it may contain an exploit that may get filtered by e-mail filters.
                matched_at = add_protocol_if_needed(vulnerability["matched-at"])
                if _is_url_without_path_query_fragment(matched_at) and get_host_from_url(target) == get_host_from_url(
                    matched_at
                ):
                    target = matched_at

                result.append(
                    Report(
                        top_level_target=get_top_level_target(task_result),
                        target=target,
                        report_type=NucleiReporter.NUCLEI_VULNERABILITY,
                        report_data={
                            "description_en": description,
                            "description_translated": NucleiReporter._translate_description(description, language),
                            "reference": vulnerability["info"]["reference"],
                            "matched_at": matched_at,
                            "template_name": vulnerability["template"],
                            "curl_command": vulnerability.get("curl-command", None),
                        },
                        timestamp=task_result["created_at"],
                    )
                )
        return result

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_nuclei_vulnerability.jinja2"), 10
            ),
        ]

    @staticmethod
    def get_scoring_rules() -> Dict[ReportType, Callable[[Report], List[int]]]:
        """See the docstring in the parent class."""
        return {NucleiReporter.NUCLEI_VULNERABILITY: lambda report: [get_url_score(report.target)]}

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {
            NucleiReporter.NUCLEI_VULNERABILITY: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_url_normal_form(report.target),
                    "template_name": report.report_data["template_name"],
                }
            )
        }

    @staticmethod
    def _translate_description(description: str, language: Language) -> str:
        if language == Language.en_US:
            return description
        elif language == Language.pl_PL:
            # See the comment in the artemis.reporting.modules.nuclei.translations.nuclei_messsages.pl_PL
            # module for the rationale of using Python dictionaries instead of .po files.
            try:
                description = description.strip()
                return translations_nuclei_messages_pl_PL.TRANSLATIONS[description]
            except KeyError:
                raise TranslationNotFoundException(
                    f"Unable to find translation for message '{description}'. "
                    f"You may add in in artemis/reporting/modules/nuclei/translations/nuclei_messages/"
                )
        else:
            raise NotImplementedError()
