import os
from collections import namedtuple
from typing import Any, Callable, Dict, List

from libmailgoose.language import Language as MailgooseLanguageClass
from libmailgoose.translate import translate

from artemis.domains import is_subdomain
from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import (
    NormalForm,
    get_domain_normal_form,
    get_domain_score,
)
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class MailDNSScannerReporter(Reporter):
    MISCONFIGURED_EMAIL = ReportType("misconfigured_email")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "mail_dns_scanner":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        MessageWithTarget = namedtuple("MessageWithTarget", "message target type")

        messages_with_targets = []
        if task_result["result"].get("spf_dmarc_scan_result", {}):
            if not task_result["result"].get("spf_dmarc_scan_result", {}).get("spf", {}).get("valid", True):
                for error in task_result["result"]["spf_dmarc_scan_result"]["spf"]["errors"]:
                    messages_with_targets.append(
                        MessageWithTarget(message=error, target=task_result["payload"]["domain"], type="SPF")
                    )
            if not task_result["result"].get("spf_dmarc_scan_result", {}).get("dmarc", {}).get("valid", True):
                report_dmarc_problems = True
                # If the record has not been found, let's report the problem only if we scanned the base domain.
                # The problem is that if a domain has a large number of subdomains, DNS timeout (and thus reporting
                # lack of DMARC record) is highly problable on at least one of them.
                if task_result["result"]["spf_dmarc_scan_result"]["dmarc"]["record_not_found"]:
                    if task_result["target_string"] not in [
                        task_result["result"]["spf_dmarc_scan_result"]["base_domain"],
                        task_result["payload_persistent"].get("original_domain", None),
                    ]:
                        report_dmarc_problems = False

                if report_dmarc_problems:
                    for error in task_result["result"]["spf_dmarc_scan_result"]["dmarc"]["errors"]:
                        target = task_result["result"]["spf_dmarc_scan_result"]["dmarc"]["location"]
                        if not target:
                            target = task_result["result"]["spf_dmarc_scan_result"]["base_domain"]

                        messages_with_targets.append(MessageWithTarget(message=error, target=target, type="DMARC"))

        result = []
        for message_with_target in messages_with_targets:
            top_level_target = get_top_level_target(task_result)

            # Sometimes we scan a domain (e.g. something.example.com) and we get a report that parent domain
            # doesn't have e-mail configured properly (e.g. example.com lacks DMARC). In such cases, we need
            # to report this to the parent domain.
            if is_subdomain(top_level_target, message_with_target.target, allow_equal=False):
                is_for_parent_domain = True
            else:
                is_for_parent_domain = False

            result.append(
                Report(
                    top_level_target=top_level_target,
                    target=message_with_target.target,
                    report_type=MailDNSScannerReporter.MISCONFIGURED_EMAIL,
                    additional_data={
                        "type": message_with_target.type,
                        "message_en": message_with_target.message,
                        "message_translated": translate(
                            message_with_target.message,
                            MailgooseLanguageClass(language.value),
                        ),
                        "is_for_parent_domain": is_for_parent_domain,
                    },
                    timestamp=task_result["created_at"],
                )
            )
        return result

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_misconfigured_email.jinja2"), priority=4
            ),
        ]

    @staticmethod
    def get_scoring_rules() -> Dict[ReportType, Callable[[Report], List[int]]]:
        """See the docstring in the parent class."""
        return {MailDNSScannerReporter.MISCONFIGURED_EMAIL: lambda report: [get_domain_score(report.target)]}

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {
            MailDNSScannerReporter.MISCONFIGURED_EMAIL: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_domain_normal_form(report.target),
                    "message": report.additional_data["message_en"],
                }
            )
        }
