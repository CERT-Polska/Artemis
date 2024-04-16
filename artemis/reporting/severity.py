import json
from enum import Enum

from artemis.config import Config
from artemis.reporting.base.report_type import ReportType


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_MAP = {
    ReportType("insecure_wordpress"): Severity.HIGH,
    ReportType("nuclei_vulnerability"): Severity.HIGH,
    ReportType("subdomain_takeover_possible"): Severity.HIGH,
    ReportType("sql_injection"): Severity.HIGH,
    ReportType("script_unregistered_domain"): Severity.HIGH,
    ReportType("closed_wordpress_plugin"): Severity.HIGH,
    ReportType("exposed_database_with_easy_password"): Severity.HIGH,
    ReportType("exposed_version_control_folder"): Severity.HIGH,
    ReportType("exposed_version_control_folder_with_credentials"): Severity.HIGH,
    ReportType("exposed_wordpress_with_easy_password"): Severity.HIGH,
    ReportType("exposed_keys"): Severity.HIGH,
    ReportType("exposed_password_file"): Severity.HIGH,
    ReportType("exposed_dead_letter"): Severity.HIGH,
    ReportType("exposed_archive"): Severity.HIGH,
    ReportType("exposed_configuration_file"): Severity.HIGH,
    ReportType("exposed_sql_dump"): Severity.HIGH,
    ReportType("exposed_ssh_with_easy_password"): Severity.HIGH,
    ReportType("exposed_log_file"): Severity.MEDIUM,
    ReportType("wordpress_outdated_plugin_theme"): Severity.MEDIUM,
    ReportType("misconfigured_email"): Severity.MEDIUM,
    ReportType("old_drupal"): Severity.MEDIUM,
    ReportType("old_joomla"): Severity.MEDIUM,
    # This doesn't mean that a version is insecure, as WordPress maintains a separate list
    # of insecure versions. This just means "turn on the automatic updates"
    ReportType("old_wordpress"): Severity.LOW,
    ReportType("close_domain_expiration_date"): Severity.MEDIUM,
    ReportType("exposed_http_server_info_status"): Severity.MEDIUM,
    ReportType("exposed_php_source"): Severity.MEDIUM,
    ReportType("zone_transfer_possible"): Severity.MEDIUM,
    ReportType("exposed_file_with_listing"): Severity.MEDIUM,
    ReportType("directory_index"): Severity.MEDIUM,
    ReportType("open_port_remote_desktop"): Severity.MEDIUM,
    ReportType("exposed_bash_history"): Severity.MEDIUM,
    ReportType("close_domain_expiry_date"): Severity.MEDIUM,
    ReportType("certificate_authority_invalid"): Severity.LOW,
    ReportType("expired_ssl_certificate"): Severity.LOW,
    ReportType("almost_expired_ssl_certificate"): Severity.LOW,
    ReportType("bad_certificate_names"): Severity.LOW,
    ReportType("no_https_redirect"): Severity.LOW,
    ReportType("exposed_php_var_dump"): Severity.LOW,
    ReportType("exposed_phpinfo"): Severity.LOW,
    ReportType("nuclei_exposed_panel"): Severity.LOW,
    ReportType("missing_security_headers"): Severity.LOW,
}

if Config.Reporting.ADDITIONAL_SEVERITY_FILE:
    with open(Config.Reporting.ADDITIONAL_SEVERITY_FILE) as f:
        additional = json.load(f)
    for report, severity in additional.items():
        SEVERITY_MAP[ReportType(report)] = Severity(severity)
