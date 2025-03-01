import os
import yaml
from typing import Annotated, Any, List, get_type_hints

import decouple

DEFAULTS = {}

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.yaml")
def load_config():
    """Loads configuration from config.yaml"""
    with open(CONFIG_FILE, "r") as file:
        return yaml.safe_load(file)
    
config = load_config()

#example
NUCLEI_TEMPLATES_TO_SKIP = config["modules"]["nuclei"]["templates_to_skip"]

#to delete
def get_config(name: str, **kwargs) -> Any:  # type: ignore
    if "default" in kwargs:
        DEFAULTS[name] = kwargs["default"]
    return decouple.config(name, **kwargs)


if "POSTGRES_CONN_STR" not in os.environ:
    raise Exception(
        "Unable to find the POSTGRES_CONN_STR environment variable. Artemis was migrated to store task results in "
        "PostgreSQL - you might have an old .env file where a PostgreSQL connection string is not provided. To use "
        "the default PostgreSQL container started by Artemis, add "
        "POSTGRES_CONN_STR=postgresql://postgres:postgres@postgres/artemis to the .env file."
    )


class Config:
    class Data:
        POSTGRES_CONN_STR: Annotated[str, "Connection string to the PostgreSQL database."] = get_config(
            "POSTGRES_CONN_STR"
        )
        REDIS_CONN_STR: Annotated[str, "Connection string to Redis."] = get_config("REDIS_CONN_STR")

        LEGACY_MONGODB_CONN_STR: Annotated[
            str,
            "Connection string to the MongoDB database. MongoDB is not used anymore - it is present here to seamlessly "
            "migrate data from older Artemis versions to PostgreSQL.",
        ] = get_config("DB_CONN_STR")

        class Autoarchiver:
            AUTOARCHIVER_INTERVAL_SECONDS: Annotated[
                int, "How frequently the archive process is triggered (in seconds)"
            ] = config["data"]["autoarchiver"]["interval_seconds"]
            AUTOARCHIVER_MIN_AGE_SECONDS: Annotated[
                int, "How old the task results need to be to be archived (in seconds)"
            ] = config["data"]["autoarchiver"]["min_age_seconds"]  # 80 days
            AUTOARCHIVER_PACK_SIZE: Annotated[
                int,
                "How many task results will go into single .json.gz archive. If there are not that many old task results, archiving will not be performed.",
            ] = config["data"]["autoarchiver"]["pack_size"]
            AUTOARCHIVER_OUTPUT_PATH: Annotated[
                str,
                "Where the archived task results will be saved (remember that this is a path inside the container).",
            ] = config["data"]["autoarchiver"]["output_path"]

    class Reporting:
        REPORTING_MAX_VULN_AGE_DAYS: Annotated[
            int, "When creating e-mail reports, what is the vulnerability maximum age (in days) for it to be reported."
        ] = config["reporting"]["max_vuln_age_days"]

        REPORTING_SEPARATE_INSTITUTIONS: Annotated[
            List[str],
            "Sometimes even if we scan example.com, we want to report subdomain.example.com to a separate contact, because "
            "it is a separate institution. This variable should contain a comma-separated list of such subdomains.",
        ] = config["reporting"]["separate_institutions"]

        REPORTING_DEDUPLICATION_COMMON_HTTP_PORTS: Annotated[
            List[int],
            """
            Ports that we will treat as "standard http/https ports" when deduplicating vulnerabilities - that is,
            if we observe identical vulnerability of two standard ports (e.g. on 80 and on 443), we will treat
            such case as the same vulnerability.

            This is configurable because e.g. we observed some hostings serving mirrors of content from
            port 80 on ports 81-84.
            """,
        ] = config["reporting"]["deduplication_common_http_ports"]

        MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_LOW: Annotated[
            int,
            "If a low-severity report has already been seen earlier - how much time needs to pass for a second report to be generated.",
        ] = config["reporting"]["min_days_between_reminders"]["severity_low"]

        MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_MEDIUM: Annotated[
            int,
            "If a medium-severity report has already been seen earlier - how much time needs to pass for a second report to be generated.",
        ] = config["reporting"]["min_days_between_reminders"]["severity_medium"]
        MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_HIGH: Annotated[
            int,
            "If a high-severity report has already been seen earlier - how much time needs to pass for a second report to be generated.",
        ] = config["reporting"]["min_days_between_reminders"]["severity_high"]
        ADDITIONAL_SEVERITY_FILE: Annotated[
            str,
            """
            A path (inside Docker container) of a file with JSON dictionary containing severities of additional report types:
            '{"report_type1": "high", "report_type2": "medium", ...}'.
            """,
        ] = config["reporting"]["additional_severity_file"]

    class Locking:
        LOCK_SCANNED_TARGETS: Annotated[
            bool,
            """
            Whether Artemis should strive to make at most one module scan a target at a given time. Therefore
            when locking is enabled, setting e.g. REQUESTS_PER_SECOND to will cause that no IP receives 2 port
            scanning packets/HTTP requests/MySQL connections/... per second.

            Due to the way this behavior is implemented, we cannot guarantee that a host will never be scanned
            by more than one module.
            """,
        ] = config["locking"]["lock_scanned_targets"]

        LOCK_SLEEP_MIN_SECONDS: Annotated[
            float,
            """
            Requires LOCK_SCANNED_TARGETS to be enabled.

            When a resource is locked using artemis.resource_lock.ResourceLock, a retry will be performed in the
            next LOCK_SLEEP_MIN_SECONDS..LOCK_SLEEP_MAX_SECONDS seconds.
            """,
        ] = config["locking"]["lock_sleep_min_seconds"]
        LOCK_SLEEP_MAX_SECONDS: Annotated[
            float,
            "see LOCK_SLEEP_MIN_SECONDS.",
        ] = config["locking"]["lock_sleep_max_seconds"]

        QUEUE_LOCATION_MAX_AGE_SECONDS: Annotated[
            int,
            """
            Requires LOCK_SCANNED_TARGETS to be enabled.

            Sometimes the task queue is very long and e.g. the first N tasks can't be taken because they concern IPs that
            are already scanned. To make scanning faster, Artemis remembers the position in the task queue for the next
            QUEUE_LOCATION_MAX_AGE_SECONDS in order not to repeat trying to lock the first tasks in the queue.
            """,
        ] = config["locking"]["queue_location_max_age_seconds"]

        SCAN_DESTINATION_LOCK_MAX_TRIES: Annotated[
            int,
            """
            Requires LOCK_SCANNED_TARGETS to be enabled.

            Amount of times module will try to get a lock on scanned destination (with sleeps inbetween)
            before rescheduling task for later.
            """,
        ] = config["locking"]["scan_destination_lock_max_tries"]

    class PublicSuffixes:
        ALLOW_SUBDOMAIN_ENUMERATION_IN_PUBLIC_SUFFIXES: Annotated[
            bool,
            "Whether we will enumerate subdomains for a public suffix (e.g. .pl) if it appears on the target list. This may cause very large "
            "number of domains to be scanned.",
        ] = config["public_suffixes"]["allow_subdomain_enumeration"]

        ADDITIONAL_PUBLIC_SUFFIXES: Annotated[
            List[str],
            "Additional domains that will be treated as public suffixes (even though they're not on the default Public Suffix List).",
        ] = config["public_suffixes"]["additional_public_suffixes"]

    class Limits:
        TASK_TIMEOUT_SECONDS: Annotated[int, "What is the maximum task run time (after which it will get killed)."] = config["limits"]["task_timeout_seconds"]

        REQUEST_TIMEOUT_SECONDS: Annotated[
            int,
            "Default request timeout (for all protocols).",
        ] = config["limits"]["request_timeout_seconds"]

        REQUESTS_PER_SECOND: Annotated[
            float,
            """
            E.g. when set to 2, Artemis will make sure no more than 2 HTTP/MySQL connect/... requests take place per second, sleeping if needed.
            """,
        ] = config["limits"]["requests_per_second"]

    class Miscellaneous:
        API_TOKEN: Annotated[str, "The token to authenticate to the API. Provide one to use the API."] = config["miscellaneous"]["api_token"]

        REMOVE_LOGS_AFTER_DAYS: Annotated[int, "After what number of days the logs in karton-logs are removed."] = config["miscellaneous"]["remove_logs_after_days"]

        BLOCKLIST_FILE: Annotated[
            str,
            "A file that determines what should not be scanned or reported",
        ] = config["miscellaneous"]["blocklist_file"]

        CUSTOM_USER_AGENT: Annotated[
            str,
            "Custom User-Agent string used by Artemis (if not set, the library defaults will be used, different for requests, Nuclei etc.)",
        ] = config["miscellaneous"]["custom_user_agent"]

        LOG_LEVEL: Annotated[
            str,
            "Log level (e.g. INFO or DEBUG) - for available levels browse to https://docs.python.org/3/library/logging.html#logging-levels",
        ] = config["miscellaneous"]["log_level"]
        LOGGING_FORMAT_STRING: Annotated[
            str,
            "Logging format string (according to the syntax in https://docs.python.org/3/library/logging.html#logrecord-attributes)",
        ] = config["miscellaneous"]["logging_format"]

        VERIFY_REVDNS_IN_SCOPE: Annotated[
            bool,
            """
            By default, Artemis will check whether the reverse DNS lookup for an IP matches
            the original domain. For example, if we encounter the 1.1.1.1 ip which resolves to
            new.example.com, Artemis will check whether it is a subdomain of the original task
            domain.

            This is to prevent Artemis from randomly walking through the internet after encountering
            a misconfigured Reverse DNS record (e.g. pointing to a completely different domain).

            The downside of that is that when you don't provide original domain (e.g. provide
            an IP to be scanned), the domain from the reverse DNS lookup won't be scanned. Therefore this
            behavior is configurable and may be turned off.
            """,
        ] = config["miscellaneous"]["verify_revdns_in_scope"]

        NUM_DNS_RESOLVER_RETRIES: Annotated[
            int,
            "Number of times a DNS query will be retried if failed. This helps reduce the number of e.g. mail-related "
            'false positives, where a failed DNS query may result with a "no DMARC" message.',
        ] = config["miscellaneous"]["num_dns_resolver_retries"]

        MAX_NUM_TASKS_TO_PROCESS: Annotated[
            int,
            "After this number of tasks processed, each scanning module will get restarted. This is to prevent situations "
            "such as slow memory leaks.",
        ] = config["miscellaneous"]["max_num_tasks_to_process"]

        CONTENT_PREFIX_SIZE: Annotated[
            int,
            "In order not to overload the DB and bandwidth, this determines how long the downloaded content would be (in bytes).",
        ] = config["miscellaneous"]["content_prefix_size"]

        MODULES_DISABLED_BY_DEFAULT: Annotated[
            List[str],
            "Artemis modules that are disabled by default (but may easily be enabled in the UI)",
        ] = config["miscellaneous"]["modules_disabled_by_default"]

        SUBDOMAIN_ENUMERATION_TTL_DAYS: Annotated[
            int,
            "If we request a domain for subdomain enumeration, we will save that it has already been enumerated, so that e.g. "
            "if we requested crtsh enumeration on example.com and received www.example.com, crtsh enumeration on www.example.com won't happen "
            "in SUBDOMAIN_ENUMERATION_TTL_DAYS days. This is the TTL of such markers.",
        ] = config["miscellaneous"]["subdomain_enumeration_ttl_days"]

        ADDITIONAL_HOSTS_FILE_PATH: Annotated[str, "File that will be appended to /etc/hosts"] = config["miscellaneous"]["additional_hosts_file_path"]

    class Modules:
        class Bruter:
            BRUTER_FILE_LIST: Annotated[
                str,
                "Possible values: 'full' or 'short'. Whether a short or full file list will be used to brute-force paths.",
            ] = config["modules"]["bruter"]["file_list"]

            BRUTER_FALSE_POSITIVE_THRESHOLD: Annotated[
                float,
                "A threshold in case bruter finds too many files on a server "
                "and we want to skip this as a false positive. 0.1 means 10%.",
            ] = config["modules"]["bruter"]["false_positive_threshold"]

            BRUTER_FOLLOW_REDIRECTS: Annotated[
                bool,
                "If set to True, bruter will follow redirects. If to False, a redirect will be interpreted that a URL "
                "doesn't exist, thus decreasing the number of false positives at the cost of losing some true positives.",
            ] = config["modules"]["bruter"]["follow_redirects"]

        class DNSScanner:
            ZONE_TRANSFER_SIZE_REPORTING_THRESHOLD: Annotated[
                int, "The number of domains below which zone transfer won't be reported."
            ] = config["modules"]["dns_scanner"]["zone_transfer_size_reporting_threshold"]

        class FTPBruter:
            FTP_BRUTER_TEST_FILE_NAME_PREFIX: Annotated[
                str,
                "The prefix that will be added to the name of the file the module will attempt to create (to check "
                "whether writing is possible).",
            ] = config["modules"]["ftp_bruter"]["test_file_name_prefix"]

        class Humble:
            HUMBLE_HEADERS_TO_REPORT: Annotated[
                List[str],
                "The list of headers that are considered more important and will be mentioned in the generated text "
                "reports (all of the missing headers will be visible in the UI).",
            ] = config["modules"]["humble"]["headers_to_report"]

        class Nuclei:
            NUCLEI_TEMPLATE_LISTS: Annotated[
                List[str],
                "Which template lists to use. Available: known_exploited_vulnerabilities (from https://github.com/Ostorlab/KEV/), "
                "critical (having severity=critical), high (having severity=high), medium (having severity=medium), "
                "log_exposures (http/exposures/logs folder in https://github.com/projectdiscovery/nuclei-templates/), "
                "exposed_panels (http/exposed-panels/ folder).",
            ] = config["modules"]["nuclei"]["template_lists"]

            NUCLEI_INTERACTSH_SERVER: Annotated[
                str,
                "Which interactsh server to use. if None, uses the default.",
            ] = config["modules"]["nuclei"]["interactsh_server"]

            NUCLEI_CHECK_TEMPLATE_LIST: Annotated[
                bool,
                "Whether to check that the downloaded Nuclei template list is not empty (may fail e.g. on Github CI "
                "when the Github API rate limits are spent).",
            ] = config["modules"]["nuclei"]["check_template_list"]

            NUCLEI_SECONDS_PER_REQUEST_ON_RETRY: Annotated[
                bool,
                "When retrying due to 'context deadline exceeded', each request will take at least max(2 * SECONDS_PER_REQUEST, "
                "NUCLEI_SECONDS_PER_REQUEST_ON_RETRY).",
            ] = config["modules"]["nuclei"]["seconds_per_request_on_retry"]

            NUCLEI_TEMPLATE_GROUPS_FILE: Annotated[
                str,
                "A path (inside Docker container) of a file with JSON dictionary of template group assignments: "
                '{"template1": "group1", "template2": "group2", ...}. If a template is assigned to a group, instead '
                "of the template, the whole group will be reported as the detected template name. Therefore, due to "
                "findings deduplication, only one instance of such vulnerability will be reported. This is useful to "
                "detect situations when multiple .env detectors detect a single file or multiple XSS templates are "
                "triggered on a single page.",
            ] = config["modules"]["nuclei"]["template_groups_file"]

            NUCLEI_MAX_BATCH_SIZE: Annotated[
                int,
                "How many sites to scan at once. This is the maximum batch size - we will try to obtain NUCLEI_MAX_BATCH_SIZE "
                "sites to scan from the queue, but if per-IP locking is enabled, then we will filter ones that are already "
                "scanned by other modules.",
            ] = config["modules"]["nuclei"]["max_batch_size"]

            NUCLEI_TEMPLATES_TO_SKIP: Annotated[
                List[str],
                "Comma-separated list of Nuclei templates not to be executed. See artemis/config.py for the rationale "
                "behind skipping particular templates.",
            ] = config["modules"]["nuclei"]["templates_to_skip"]

            NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY_FILE: Annotated[
                str,
                "File with a list of Nuclei templates (one per line) to be skipped with NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY_PROBABILITY "
                "probability. Use this if you have some templates that never yield results - you don't want to skip them altogether (because "
                "they may start giving results) but maybe don't run them on all hosts.",
            ] = config["modules"]["nuclei"]["templates_to_skip_probabilistically_file"]

            NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY_PROBABILITY: Annotated[
                float,
                "Probability (0...100) of each template from NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY to be skipped. "
                "Use this if you have some templates that never yield results - you don't want to skip them altogether (because "
                "they may start giving results) but maybe don't run them on all hosts.",
            ] = config["modules"]["nuclei"]["templates_to_skip_probabilistically_probability"]

            NUCLEI_ADDITIONAL_TEMPLATES: Annotated[
                List[str],
                "A comma-separated list of Nuclei templates to be used besides the standard list. "
                "vulnerabilities/generic/crlf-injection.yaml was present here but is not anymore due to "
                "a significant number of false positives.",
            ] = config["modules"]["nuclei"]["additional_templates"]

            NUCLEI_SUSPICIOUS_TEMPLATES: Annotated[
                List[str],
                "A comma-separated list of Nuclei templates to be reviewed manually if found as they "
                "are known to return false positives.",
            ] = config["modules"]["nuclei"]["suspicious_templates"]

            NUCLEI_TEMPLATES_TO_RUN_ON_HOMEPAGE_LINKS: Annotated[
                List[str],
                "Normally, Nuclei templates are ran only on the root url. These templates will also run "
                "on all URLs linked from the root URL to detect vulnerabilities on non-root pages.",
            ] = config["modules"]["nuclei"]["templates_to_run_on_homepage_links"]

            NUCLEI_MAX_NUM_LINKS_TO_PROCESS: Annotated[
                int,
                "Maximum number of links to be checked with the templates provided in "
                "NUCLEI_TEMPLATES_TO_RUN_ON_HOMEPAGE_LINKS (if more are seen, random "
                "NUCLEI_MAX_NUM_LINKS_TO_PROCESS are chosen).",
            ] = config["modules"]["nuclei"]["max_num_links_to_process"]

            NUCLEI_TEMPLATE_CHUNK_SIZE: Annotated[
                int,
                "How big are the chunks to split the template list. E.g. if the template list contains 600 templates and "
                "NUCLEI_TEMPLATE_CHUNK_SIZE is 200, three calls will be made with 200 templates each.",
            ] = config["modules"]["nuclei"]["template_chunk_size"]


        class PlaceholderPageContent:
            ENABLE_PLACEHOLDER_PAGE_DETECTOR: Annotated[
                bool,
                "Enable or disable placeholder pages detector. Using this feature you may skip vulnerability scanning "
                "for websites that aren't built yet, but e.g. contain a hosting provider placeholder page. "
                "If the page exists and the specified string is found within it, the page will not be scanned for "
                "vulnerabilities. If the page is not marked as a placeholder, a full scan will be performed.",
            ] = config["modules"]["placeholder_page_content"]["enable_detector"]
            PLACEHOLDER_PAGE_CONTENT_FILENAME: Annotated[
                str,
                "Path to placeholder page content file. The file is divided into lines – each line is a string "
                "containing a different HTML code element to check.",
            ] = config["modules"]["placeholder_page_content"]["content_filename"]

        class PortScanner:
            PORT_SCANNER_PORT_LIST: Annotated[str, "Chosen list of ports to scan (can be 'short' or 'long')"] = config["modules"]["port_scanner"]["port_list"]

            CUSTOM_PORT_SCANNER_PORTS: Annotated[
                List[int],
                "Custom port list to scan in CSV form (replaces default list).",
            ] = config["modules"]["port_scanner"]["custom_ports"]

            PORT_SCANNER_TIMEOUT_MILLISECONDS: Annotated[
                int,
                "Port scanner: milliseconds to wait before timing out",
            ] = config["modules"]["port_scanner"]["timeout_milliseconds"]

            PORT_SCANNER_MAX_NUM_PORTS: Annotated[
                int,
                "The number of open ports we consider to be too much and a false positive - if we observe more "
                "open ports, we trim by performing an intersection of the result with the list of 100 most popular ones.",
            ] = config["modules"]["port_scanner"]["max_num_ports"]

        class Postman:
            POSTMAN_MAIL_FROM: Annotated[
                str,
                "Sender e-mail address that will be used to test whether a server is an open relay or allows "
                "sending e-mails to any address.",
            ] = config["modules"]["postman"]["mail_from"]
            POSTMAN_MAIL_TO: Annotated[
                str,
                "Recipient e-mail address, e.g. for open relay testing.",
            ] = config["modules"]["postman"]["mail_to"]

        class RemovedDomainExistingVhost:
            REMOVED_DOMAIN_EXISTING_VHOST_PASSIVEDNS_URLS: Annotated[
                str,
                "Comma-separated list of URLs (optionally with username:password) to download old domain IPs from. "
                "Currently, the system was tested with circl.lu passive DNS. **The URL should end with /pdns/query/**.",
            ] = config["modules"]["removed_domain_existing_vhost"]["passivedns_urls"]

            REMOVED_DOMAIN_EXISTING_VHOST_REPORT_ONLY_SUBDOMAINS: Annotated[
                str,
                "If set to True, 'removed domain but existing vhost' situations will be reported only for subdomains.",
            ] = config["modules"]["removed_domain_existing_vhost"]["report_only_subdomains"]

            REMOVED_DOMAIN_EXISTING_VHOST_PASSIVEDNS_SLEEP_BETWEEN_REQUESTS_SECONDS: Annotated[
                float,
                "How long to sleep between passivedns requests in order not to overload the provider.",
            ] = config["modules"]["removed_domain_existing_vhost"]["passivedns_sleep_between_requests_seconds"]

            REMOVED_DOMAIN_EXISTING_VHOST_SIMILARITY_THRESHOLD: Annotated[
                float,
                "How similar the results for correct and different domain should be to consider that the server "
                "doesn't host the given domain.",
            ] = config["modules"]["removed_domain_existing_vhost"]["similarity_threshold"]

        class Shodan:
            SHODAN_API_KEY: Annotated[
                str,
                "Shodan API key so that Shodan vulnerabilities will be displayed in Artemis.",
            ] = config["modules"]["shodan"]["api_key"]

        class SSHBruter:
            ADDITIONAL_BRUTE_FORCE_SLEEP_SECONDS: Annotated[
                int,
                "Some SSH servers drop connections after a large number of tries in a short "
                "time period. This is to combat this behavior.",
            ] = config["modules"]["ssh_bruter"]["additional_brute_force_sleep_seconds"]

        class SubdomainEnumeration:
            RETRIES: Annotated[
                int,
                "Number of retries for subdomain enumeration.",
            ] = config["modules"]["subdomain_enumeration"]["retries"]

            SLEEP_TIME_SECONDS: Annotated[
                int,
                "Time to sleep between retries for subdomain enumeration in seconds.",
            ] = config["modules"]["subdomain_enumeration"]["sleep_time_seconds"]

            GAU_ADDITIONAL_OPTIONS: Annotated[
                List[str],
                "Additional command-line options that will be passed to gau (https://github.com/lc/gau).",
            ] = config["modules"]["subdomain_enumeration"]["gau_additional_options"]

        class VCS:
            VCS_MAX_DB_SIZE_BYTES: Annotated[
                int,
                "Maximum size of the VCS (e.g. SVN) db file.",
            ] = config["modules"]["vcs"]["max_db_size_bytes"]

        class WordPressPlugins:
            WORDPRESS_SKIP_VERSION_CHECK_ON_LESS_POPULAR_PLUGINS: Annotated[
                bool,
                "Some plugins have wrong versions in the README. For the most popular 1500 plugins, Artemis team monitors "
                "such cases and excludes the plugins that have wrong versions in the README from scanning. For the less popular "
                "plugins (e.g. if one can be identified by /wp-content/plugins/xyz/ URL in the website source), such "
                "cases can be a source of false positives.\n\n"
                "If this option is set to True, version check for such plugins will not be performed.",
            ] = config["modules"]["wordpress_plugins"]["skip_version_check_on_less_popular_plugins"]

        class WordPressScanner:
            WORDPRESS_VERSION_AGE_DAYS: Annotated[
                int,
                "After what number of days we consider the WordPress version to be obsolete. This is a long "
                'threshold because WordPress maintains a separate list of insecure versions, so "old" doesn\'t '
                'mean "insecure" here.',
            ] = config["modules"]["wordpress_scanner"]["version_age_days"]

        class WordPressBruter:
            WORDPRESS_BRUTER_STRIPPED_PREFIXES: Annotated[
                List[str],
                "Wordpress_bruter extracts the site name to brute-force passwords. For example, if it observes "
                "projectname.example.com it will bruteforce projectname123, projectname2023, ... "
                "This list describes what domain prefixes to strip (e.g. www) so that we bruteforce projectname123, not "
                "www123, when testing www.projectname.example.com.",
            ] = config["modules"]["wordpress_bruter"]["stripped_prefixes"]

        class DomainExpirationScanner:
            DOMAIN_EXPIRATION_TIMEFRAME_DAYS: Annotated[
                int, "The scanner warns if the domain's expiration date falls within this time frame from now."
            ] = config["modules"]["domain_expiration_scanner"]["timeframe_days"]

        class SqlInjectionDetector:
            SQL_INJECTION_STOP_ON_FIRST_MATCH: Annotated[
                bool,
                "Whether to display only the first SQL injection and stop scanning.",
            ] = config["modules"]["sql_injection_detector"]["stop_on_first_match"]
            SQL_INJECTION_NUM_RETRIES_TIME_BASED: Annotated[
                int,
                "How many times to re-check whether long request duration with inject (and short without inject) is indeed a vulnerability or a random fluctuation ",
            ] = config["modules"]["sql_injection_detector"]["num_retries_time_based"]
            SQL_INJECTION_TIME_THRESHOLD: Annotated[
                int,
                "Seconds to sleep using the sleep() or pg_sleep() methods",
            ] = config["modules"]["sql_injection_detector"]["time_threshold"]

    @staticmethod
    def verify_each_variable_is_annotated() -> None:
        def verify_class(cls: type) -> None:
            hints = get_type_hints(cls)

            for variable_name in dir(cls):
                if variable_name.startswith("__"):
                    continue
                member = getattr(cls, variable_name)

                if isinstance(member, type):
                    verify_class(member)
                elif member == Config.verify_each_variable_is_annotated:
                    pass
                else:
                    assert variable_name in hints, f"{variable_name} in {cls} has no type hint"

        verify_class(Config)


Config.verify_each_variable_is_annotated()
