import os
from typing import Any, Dict, List

from artemis.models import FoundURL
from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.modules.bruter.classifier import (
    contains_crypto_keys,
    is_configuration_file,
    is_dead_letter,
    is_exposed_archive,
    is_exposed_file_with_listing,
    is_ini_file,
    is_log_file,
    is_password_file,
    is_php_source,
    is_php_var_dump,
    is_sql_dump,
)
from artemis.reporting.utils import get_top_level_target


class BruterReporter(Reporter):
    EXPOSED_ARCHIVE = ReportType("exposed_archive")
    EXPOSED_CONFIGURATION_FILE = ReportType("exposed_configuration_file")
    EXPOSED_DEAD_LETTER = ReportType("exposed_dead_letter")
    EXPOSED_FILE_WITH_LISTING = ReportType("exposed_file_with_listing")
    EXPOSED_KEYS = ReportType("exposed_keys")
    EXPOSED_LOG_FILE = ReportType("exposed_log_file")
    EXPOSED_PASSWORD_FILE = ReportType("exposed_password_file")
    EXPOSED_PHPINFO = ReportType("exposed_phpinfo")
    EXPOSED_PHP_SOURCE = ReportType("exposed_php_source")
    EXPOSED_PHP_VAR_DUMP = ReportType("exposed_php_var_dump")
    EXPOSED_SQL_DUMP = ReportType("exposed_sql_dump")

    # These two are not reported anymore, as they're found by Nuclei. We leave them here so that
    # already existing, old reports will be supported.
    EXPOSED_BASH_HISTORY = ReportType("exposed_bash_history")
    EXPOSED_HTTP_SERVER_INFO_STATUS = ReportType("exposed_http_server_info_status")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "bruter":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        reports = []

        def add_report(found_url: FoundURL, report_type: ReportType) -> None:
            reports.append(
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=found_url.url,
                    report_type=report_type,
                    additional_data={},
                    timestamp=task_result["created_at"],
                )
            )

        for found_url_dict in task_result["result"].get("found_urls", {}):
            found_url = FoundURL(**found_url_dict)

            if is_password_file(found_url):
                add_report(found_url, BruterReporter.EXPOSED_PASSWORD_FILE)
            elif is_sql_dump(found_url):
                add_report(found_url, BruterReporter.EXPOSED_SQL_DUMP)
            elif is_exposed_archive(found_url):
                add_report(found_url, BruterReporter.EXPOSED_ARCHIVE)
            elif is_configuration_file(found_url) or is_ini_file(found_url):
                add_report(found_url, BruterReporter.EXPOSED_CONFIGURATION_FILE)
            # The ordering is important - if something is not a config file, a generic leaked php source report
            # should be returned.
            elif is_php_source(found_url):
                add_report(found_url, BruterReporter.EXPOSED_PHP_SOURCE)
            elif is_log_file(found_url):
                add_report(found_url, BruterReporter.EXPOSED_LOG_FILE)
            elif is_exposed_file_with_listing(found_url):
                add_report(found_url, BruterReporter.EXPOSED_FILE_WITH_LISTING)
            elif is_dead_letter(found_url):
                add_report(found_url, BruterReporter.EXPOSED_DEAD_LETTER)
            elif contains_crypto_keys(found_url):
                add_report(found_url, BruterReporter.EXPOSED_KEYS)
            elif is_php_var_dump(found_url):
                add_report(found_url, BruterReporter.EXPOSED_PHP_VAR_DUMP)
            # PHP 7 has title PHP 7.3.27 - phpinfo() so we match only the end
            elif found_url.url.endswith(".php") and "phpinfo()</title>" in found_url.content_prefix:
                add_report(found_url, BruterReporter.EXPOSED_PHPINFO)
        return reports

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_exposed_password_file.jinja2"), priority=10
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_exposed_sql_dump.jinja2"), priority=10
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_exposed_keys.jinja2"), priority=10
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_exposed_configuration_file.jinja2"), priority=10
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_exposed_archive.jinja2"), priority=7
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_exposed_dead_letter.jinja2"), priority=7
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_exposed_log_file.jinja2"), priority=5
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_exposed_file_with_listing.jinja2"), priority=4
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_exposed_php_source.jinja2"), priority=4
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_exposed_php_var_dump.jinja2"), priority=4
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_exposed_phpinfo.jinja2"), priority=3
            ),
        ]
