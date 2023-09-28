import collections
import os
import urllib.parse
from typing import Any, Callable, Counter, Dict, List

from artemis.config import Config
from artemis.modules.nuclei import EXPOSED_PANEL_TEMPLATE_PATH_PREFIX
from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import NormalForm, get_url_normal_form
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.exceptions import TranslationNotFoundException
from artemis.reporting.utils import (
    add_protocol_if_needed,
    get_target_url,
    get_top_level_target,
)
from artemis.utils import get_host_from_url

from .translations.nuclei_messages import pl_PL as translations_nuclei_messages_pl_PL


class NucleiReporter(Reporter):
    NUCLEI_VULNERABILITY = ReportType("nuclei_vulnerability")
    NUCLEI_EXPOSED_PANEL = ReportType("nuclei_exposed_panel")

    @staticmethod
    def get_alerts(all_reports: List[Report], false_positive_threshold: int = 3) -> List[str]:
        result = []

        reports_by_target_counter: Counter[str] = collections.Counter()
        for report in all_reports:
            if report.report_type in [NucleiReporter.NUCLEI_VULNERABILITY, NucleiReporter.NUCLEI_EXPOSED_PANEL]:
                reports_by_target_counter[report.target] += 1

                if report.additional_data["template_name"] in Config.Modules.Nuclei.NUCLEI_SUSPICIOUS_TEMPLATES:
                    result.append(
                        f"Suspicious template: {report.additional_data['template_name']} in {report.target} "
                        f"(curl_command: {report.additional_data['curl_command']}) - please review whether it's indeed "
                        "a true positive."
                    )

        for key, value in reports_by_target_counter.items():
            if value >= false_positive_threshold:
                result.append(f"Found {value} Nuclei reports for {key}. Please make sure they are not false positives.")
        return result

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

        templates_seen = set()

        for vulnerability in task_result["result"]:
            if not isinstance(vulnerability, dict):
                continue

            if "template" in vulnerability:
                template = vulnerability["template"]
            else:
                template = "custom:" + vulnerability["template-id"]

            # Some templates are slightly broken and are returned multiple times, let's skip subsequent ones.
            if template in templates_seen:
                continue

            templates_seen.add(template)

            if template in Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_SKIP:
                continue

            if "description" in vulnerability["info"]:
                description = vulnerability["info"]["description"]
            else:
                description = "[no description] " + template

            if template.startswith(EXPOSED_PANEL_TEMPLATE_PATH_PREFIX):
                result.append(
                    Report(
                        top_level_target=get_top_level_target(task_result),
                        target=vulnerability["matched-at"],
                        report_type=NucleiReporter.NUCLEI_EXPOSED_PANEL,
                        additional_data={
                            "description_en": description,
                            "description_translated": NucleiReporter._translate_description(
                                template, description, language
                            ),
                            "matched_at": vulnerability["matched-at"],
                            "template_name": template,
                            "curl_command": vulnerability.get("curl-command", None),
                        },
                        timestamp=task_result["created_at"],
                    )
                )
            else:
                target = get_target_url(task_result)

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
                        additional_data={
                            "description_en": description,
                            "description_translated": NucleiReporter._translate_description(
                                template, description, language
                            ),
                            "reference": vulnerability["info"]["reference"],
                            "matched_at": matched_at,
                            "template_name": template,
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
                os.path.join(os.path.dirname(__file__), "template_nuclei_vulnerability.jinja2"), priority=10
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_nuclei_exposed_panel.jinja2"), priority=0
            ),
        ]

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {
            report_type: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_url_normal_form(report.target),
                    "template_name": report.additional_data["template_name"],
                }
            )
            for report_type in NucleiReporter.get_report_types()
        }

    @staticmethod
    def _translate_description(template_name: str, description: str, language: Language) -> str:
        if language == Language.en_US:
            return description
        elif language == Language.pl_PL:
            # See the comment in the artemis.reporting.modules.nuclei.translations.nuclei_messsages.pl_PL
            # module for the rationale of using Python dictionaries instead of .po files.
            description = description.strip()

            # We allow both matching by description and template name. Matching by description allows
            # easier translation and code review, matching by template name needs to be supported
            # in case multiple templates have the same description.
            if description in translations_nuclei_messages_pl_PL.TRANSLATIONS:
                return translations_nuclei_messages_pl_PL.TRANSLATIONS[description]
            if template_name in translations_nuclei_messages_pl_PL.TRANSLATIONS:
                return translations_nuclei_messages_pl_PL.TRANSLATIONS[template_name]
            raise TranslationNotFoundException(
                f"Unable to find translation for message '{description}' (template_name: {template_name}). "
                f"You may add in in artemis/reporting/modules/nuclei/translations/nuclei_messages/"
            )
        else:
            raise NotImplementedError()
