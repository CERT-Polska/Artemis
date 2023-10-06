import os
from collections import namedtuple
from typing import Any, Callable, Dict, List

from artemis.domains import is_subdomain
from artemis.mail_check.translate import Language as MailCheckLanguageClass
from artemis.mail_check.translate import _
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


def fix_error(error):
    if error == "SPF record causes too many void DNS lookups":
        error = (
            "SPF record causes too many void DNS lookups. Some implementations may require the number of "
            "failed DNS lookups (e.g. ones that reference a nonexistent domain) to be low. The DNS lookups "
            "are caused by directives such as 'mx' or 'include'."
        )
    if error == "Valid DMARC record not found" or error == "DMARC record not found":
        error = (
            "Valid DMARC record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC "
            "to decrease the possibility of successful e-mail message spoofing."
        )
    if error == "Valid SPF record not found" or error == "SPF record not found":
        error = (
            "Valid SPF record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC "
            "to decrease the possibility of successful e-mail message spoofing."
        )
    if error == "SPF ~all or -all directive not found":
        error = (
            "SPF '~all' or '-all' directive not found. We recommend adding it, as it describes "
            "what should happen with messages that fail SPF verification. For example, "
            "'-all' will tell the recipient server to drop such messages."
        )
    if error == "DMARC policy is none and rua is not set, which means that the DMARC setting is not effective.":
        error = "DMARC policy is 'none' and 'rua' is not set, which means that the DMARC setting is not effective."
    if error == "Multiple SPF records found":
        error = (
            "Multiple SPF records found. We recommend leaving only one, as multiple SPF records "
            "can cause problems with some SPF implementations."
        )
    if error == "SPF record includes an endless loop":
        error = (
            "SPF record includes an endless loop. Please check whether 'include' or 'redirect' directives don't "
            "create a loop where a domain redirects back to itself or earlier domain."
        )
    if error == "SPF record is not syntatically correct":
        error = "SPF record is not syntactically correct. Please closely inspect its syntax."
    if error == "DMARC record is not syntatically correct":
        error = "DMARC record is not syntactically correct. Please closely inspect its syntax."
    if error in [
        "SPF record not found in domain referenced from other SPF record",
        "Valid SPF record not found in domain referenced from other SPF record",
    ]:
        error = (
            "The SPF record references a domain that doesn't have an SPF record. When using directives such "
            "as 'include' or 'redirect', remember, that the destination domain should have a proper SPF record."
        )
    if error == "SPF record includes too many DNS lookups":
        error = (
            "SPF record causes too many void DNS lookups. Some implementations may require the number of "
            "failed DNS lookups (e.g. ones that reference a nonexistent domain) to be low. The DNS lookups "
            "are caused by directives such as 'mx' or 'include'."
        )
    if error == "Valid DMARC record not found":
        error = "Valid DMARC record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC to decrease the possibility of successful e-mail message spoofing."
    return error


class MailDNSScannerReporter(Reporter):
    MISCONFIGURED_EMAIL = ReportType("misconfigured_email")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "mail_dns_scanner":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        MessageWithTarget = namedtuple("MessageWithTarget", "message target")

        messages_with_targets = []
        if task_result["result"].get("spf_dmarc_scan_result", {}):
            if not task_result["result"].get("spf_dmarc_scan_result", {}).get("spf", {}).get("valid", True):
                for error in task_result["result"]["spf_dmarc_scan_result"]["spf"]["errors"]:
                    error = fix_error(error)
                    messages_with_targets.append(
                        MessageWithTarget(message=error, target=task_result["payload"]["domain"])
                    )
            if not task_result["result"].get("spf_dmarc_scan_result", {}).get("dmarc", {}).get("valid", True):
                for error in task_result["result"]["spf_dmarc_scan_result"]["dmarc"]["errors"]:
                    target = task_result["result"]["spf_dmarc_scan_result"]["dmarc"]["location"]
                    if not target:
                        target = task_result["result"]["spf_dmarc_scan_result"]["base_domain"]

                    error = fix_error(error)
                    messages_with_targets.append(MessageWithTarget(message=error, target=target))

        result = []
        for message_with_target in messages_with_targets:
            top_level_target = get_top_level_target(task_result)

            # Sometimes we scan a domain (e.g. something.example.com) and we get a report that parent domain
            # doesn't have e-mail configured properly (e.g. example.com lacks DMARC). In such cases, we need
            # to report this to the parent domain.
            if is_subdomain(top_level_target, message_with_target.target, allow_equal=False):
                top_level_target = message_with_target.target
                is_for_parent_domain = True
            else:
                is_for_parent_domain = False

            result.append(
                Report(
                    top_level_target=top_level_target,
                    target=message_with_target.target,
                    report_type=MailDNSScannerReporter.MISCONFIGURED_EMAIL,
                    additional_data={
                        "message_en": message_with_target.message,
                        "message_translated": _(message_with_target.message, MailCheckLanguageClass(language.value)),
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
