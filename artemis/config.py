import os
from typing import Annotated, Any, List, get_type_hints

import decouple

DEFAULTS = {}


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
            ] = get_config("AUTOARCHIVER_INTERVAL_SECONDS", default=3600, cast=int)
            AUTOARCHIVER_MIN_AGE_SECONDS: Annotated[
                int, "How old the task results need to be to be archived (in seconds)"
            ] = get_config(
                "AUTOARCHIVER_MIN_AGE_SECONDS", default=80 * 24 * 60 * 60, cast=int
            )  # 80 days
            AUTOARCHIVER_PACK_SIZE: Annotated[
                int,
                "How many task results will go into single .json.gz archive. If there are not that many old task results, archiving will not be performed.",
            ] = get_config("AUTOARCHIVER_PACK_SIZE", default=20_000, cast=int)
            AUTOARCHIVER_OUTPUT_PATH: Annotated[
                str,
                "Where the archived task results will be saved (remember that this is a path inside the container).",
            ] = get_config("AUTOARCHIVER_OUTPUT_PATH", default="/opt/archived-task-results/")

    class Reporting:
        REPORTING_MAX_VULN_AGE_DAYS: Annotated[
            int, "When creating e-mail reports, what is the vulnerability maximum age (in days) for it to be reported."
        ] = get_config("REPORTING_MAX_VULN_AGE_DAYS", default=60, cast=int)

        REPORTING_SEPARATE_INSTITUTIONS: Annotated[
            List[str],
            "Sometimes even if we scan example.com, we want to report subdomain.example.com to a separate contact, because "
            "it is a separate institution. This variable should contain a comma-separated list of such subdomains.",
        ] = get_config("REPORTING_SEPARATE_INSTITUTIONS", default="", cast=decouple.Csv(str))

        REPORTING_DEDUPLICATION_COMMON_HTTP_PORTS: Annotated[
            List[int],
            """
            Ports that we will treat as "standard http/https ports" when deduplicating vulnerabilities - that is,
            if we observe identical vulnerability of two standard ports (e.g. on 80 and on 443), we will treat
            such case as the same vulnerability.

            This is configurable because e.g. we observed some hostings serving mirrors of content from
            port 80 on ports 81-84.
            """,
        ] = get_config("REPORTING_DEDUPLICATION_COMMON_HTTP_PORTS", default="80,443", cast=decouple.Csv(int))

        MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_LOW: Annotated[
            int,
            "If a low-severity report has already been seen earlier - how much time needs to pass for a second report to be generated.",
        ] = get_config("MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_LOW", default=8 * 30, cast=int)

        MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_MEDIUM: Annotated[
            int,
            "If a medium-severity report has already been seen earlier - how much time needs to pass for a second report to be generated.",
        ] = get_config("MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_MEDIUM", default=4 * 30, cast=int)
        MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_HIGH: Annotated[
            int,
            "If a high-severity report has already been seen earlier - how much time needs to pass for a second report to be generated.",
        ] = get_config("MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_HIGH", default=2 * 30, cast=int)
        ADDITIONAL_SEVERITY_FILE: Annotated[
            str,
            """
            A path (inside Docker container) of a file with JSON dictionary containing severities of additional report types:
            '{"report_type1": "high", "report_type2": "medium", ...}'.
            """,
        ] = get_config("ADDITIONAL_SEVERITY_FILE", default=None)

    class Locking:
        LOCK_SCANNED_TARGETS: Annotated[
            bool,
            """
            Whether Artemis should strive to make at most one module scan a target at a given time. Therefore
            when locking is enabled, setting e.g. SCANNING_PACKETS_PER_SECOND to 100 and SECONDS_PER_REQUEST to
            2 will cause that no IP receives 100 port scanning packets per second and 1 HTTP/MySQL/... request
            per 2 seconds.

            Due to the way this behavior is implemented, we cannot guarantee that a host will never be scanned
            by more than one module.
            """,
        ] = get_config("LOCK_SCANNED_TARGETS", default=False, cast=bool)

        LOCK_SLEEP_MIN_SECONDS: Annotated[
            float,
            """
            Requires LOCK_SCANNED_TARGETS to be enabled.

            When a resource is locked using artemis.resource_lock.ResourceLock, a retry will be performed in the
            next LOCK_SLEEP_MIN_SECONDS..LOCK_SLEEP_MAX_SECONDS seconds.
            """,
        ] = get_config("LOCK_SLEEP_MIN_SECONDS", default=0.1, cast=float)
        LOCK_SLEEP_MAX_SECONDS: Annotated[
            float,
            "see LOCK_SLEEP_MIN_SECONDS.",
        ] = get_config("LOCK_SLEEP_MAX_SECONDS", default=0.5, cast=float)

        SCAN_DESTINATION_LOCK_MAX_TRIES: Annotated[
            int,
            """
            Requires LOCK_SCANNED_TARGETS to be enabled.

            Amount of times module will try to get a lock on scanned destination (with sleeps inbetween)
            before rescheduling task for later.
            """,
        ] = get_config("SCAN_DESTINATION_LOCK_MAX_TRIES", default=2, cast=int)

    class PublicSuffixes:
        ALLOW_SCANNING_PUBLIC_SUFFIXES: Annotated[
            bool,
            "Whether we will scan a public suffix (e.g. .pl) if it appears on the target list. This may cause very large "
            "number of domains to be scanned.",
        ] = get_config("ALLOW_SCANNING_PUBLIC_SUFFIXES", default=False, cast=bool)

        ADDITIONAL_PUBLIC_SUFFIXES: Annotated[
            List[str],
            "Additional domains that will be treated as public suffixes (even though they're not on the default Public Suffix List).",
        ] = get_config("ADDITIONAL_PUBLIC_SUFFIXES", default="", cast=decouple.Csv(str))

    class Limits:
        TASK_TIMEOUT_SECONDS: Annotated[int, "What is the maximum task run time (after which it will get killed)."] = (
            get_config("TASK_TIMEOUT_SECONDS", default=6 * 3600, cast=int)
        )

        REQUEST_TIMEOUT_SECONDS: Annotated[
            int,
            "Default request timeout (for all protocols).",
        ] = get_config("REQUEST_TIMEOUT_SECONDS", default=10, cast=int)

        SCANNING_PACKETS_PER_SECOND: Annotated[
            int,
            "E.g. when set to 100, Artemis will send no more than 100 port scanning packets per seconds per port scanner instance.",
        ] = get_config("SCANNING_PACKETS_PER_SECOND", default=100, cast=int)

        REQUESTS_PER_SECOND: Annotated[
            float,
            """
            E.g. when set to 2, Artemis will make sure no more than 2 HTTP/MySQL connect/... requests take place per second, sleeping if needed.
            """,
        ] = get_config("REQUESTS_PER_SECOND", default=0, cast=float)

    class Miscellaneous:
        API_TOKEN: Annotated[str, "The token to authenticate to the API. Provide one to use the API."] = get_config(
            "API_TOKEN", default=None
        )

        REMOVE_LOGS_AFTER_DAYS: Annotated[int, "After what number of days the logs in karton-logs are removed."] = (
            get_config("REMOVE_LOGS_AFTER_DAYS", default=30)
        )

        BLOCKLIST_FILE: Annotated[
            str,
            "A file that determines what should not be scanned or reported",
        ] = get_config("BLOCKLIST_FILE", default=None)

        CUSTOM_USER_AGENT: Annotated[
            str,
            "Custom User-Agent string used by Artemis (if not set, the library defaults will be used, different for requests, Nuclei etc.)",
        ] = get_config("CUSTOM_USER_AGENT", default="")

        LOG_LEVEL: Annotated[
            str,
            "Log level (e.g. INFO or DEBUG) - for available levels browse to https://docs.python.org/3/library/logging.html#logging-levels",
        ] = get_config(
            "LOG_LEVEL",
            default="INFO",
        )
        LOGGING_FORMAT_STRING: Annotated[
            str,
            "Logging format string (according to the syntax in https://docs.python.org/3/library/logging.html#logrecord-attributes)",
        ] = get_config(
            "LOGGING_FORMAT_STRING",
            default="[%(levelname)s] - [%(asctime)s] %(filename)s - in %(funcName)s() (line %(lineno)d): %(message)s",
        )

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
        ] = get_config("VERIFY_REVDNS_IN_SCOPE", default=True, cast=bool)

        NUM_DNS_RESOLVER_RETRIES: Annotated[
            int,
            "Number of times a DNS query will be retried if failed. This helps reduce the number of e.g. mail-related "
            'false positives, where a failed DNS query may result with a "no DMARC" message.',
        ] = get_config("NUM_DNS_RESOLVER_RETRIES", default=3, cast=int)

        MAX_NUM_TASKS_TO_PROCESS: Annotated[
            int,
            "After this number of tasks processed, each scanning module will get restarted. This is to prevent situations "
            "such as slow memory leaks.",
        ] = get_config("MAX_NUM_TASKS_TO_PROCESS", default=200, cast=int)

        CONTENT_PREFIX_SIZE: Annotated[
            int,
            "In order not to overload the DB and bandwidth, this determines how long the downloaded content would be (in bytes).",
        ] = get_config("CONTENT_PREFIX_SIZE", default=1024 * 100, cast=int)

        MODULES_DISABLED_BY_DEFAULT: Annotated[
            List[str],
            "Artemis modules that are disabled by default (but may easily be enabled in the UI)",
        ] = get_config("MODULES_DISABLED_BY_DEFAULT", default="example,humble", cast=decouple.Csv(str, delimiter=","))

        SUBDOMAIN_ENUMERATION_TTL_DAYS: Annotated[
            int,
            "If we request a domain for subdomain enumeration, we will save that it has already been enumerated, so that e.g. "
            "if we requested crtsh enumeration on example.com and received www.example.com, crtsh enumeration on www.example.com won't happen "
            "in SUBDOMAIN_ENUMERATION_TTL_DAYS days. This is the TTL of such markers.",
        ] = get_config("SUBDOMAIN_ENUMERATION_TTL_DAYS", default=10, cast=int)

    class Modules:
        class Bruter:
            BRUTER_FILE_LIST: Annotated[
                str,
                "Possible values: 'full' or 'short'. Whether a short or full file list will be used to brute-force paths.",
            ] = get_config("BRUTER_FILE_LIST", default="short")

            BRUTER_FALSE_POSITIVE_THRESHOLD: Annotated[
                float,
                "A threshold in case bruter finds too many files on a server "
                "and we want to skip this as a false positive. 0.1 means 10%.",
            ] = get_config("BRUTER_FALSE_POSITIVE_THRESHOLD", default=0.1, cast=float)

            BRUTER_FOLLOW_REDIRECTS: Annotated[
                bool,
                "If set to True, bruter will follow redirects. If to False, a redirect will be interpreted that a URL "
                "doesn't exist, thus decreasing the number of false positives at the cost of losing some true positives.",
            ] = get_config("BRUTER_FOLLOW_REDIRECTS", default=True, cast=bool)

        class DNSScanner:
            ZONE_TRANSFER_SIZE_REPORTING_THRESHOLD: Annotated[
                int, "The number of domains below which zone transfer won't be reported."
            ] = get_config("ZONE_TRANSFER_SIZE_REPORTING_THRESHOLD", cast=int, default=2)

        class FTPBruter:
            FTP_BRUTER_TEST_FILE_NAME_PREFIX: Annotated[
                str,
                "The prefix that will be added to the name of the file the module will attempt to create (to check "
                "whether writing is possible).",
            ] = get_config("FTP_BRUTER_TEST_FILE_NAME_PREFIX", default="test-")

        class Humble:
            HUMBLE_HEADERS_TO_REPORT: Annotated[
                List[str],
                "The list of headers that are considered more important and will be mentioned in the generated text "
                "reports (all of the missing headers will be visible in the UI).",
            ] = get_config(
                "HUMBLE_HEADERS_TO_REPORT",
                default=",".join(["Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options"]),
                cast=decouple.Csv(str, delimiter=","),
            )

        class Nuclei:
            NUCLEI_CHECK_TEMPLATE_LIST: Annotated[
                bool,
                "Whether to check that the downloaded Nuclei template list is not empty (may fail e.g. on Github CI "
                "when the Github API rate limits are spent).",
            ] = get_config("NUCLEI_CHECK_TEMPLATE_LIST", default=True, cast=bool)

            NUCLEI_TEMPLATE_GROUPS_FILE: Annotated[
                str,
                "A path (inside Docker container) of a file with JSON dictionary of template group assignments: "
                '{"template1": "group1", "template2": "group2", ...}. If a template is assigned to a group, instead '
                "of the template, the whole group will be reported as the detected template name. Therefore, due to "
                "findings deduplication, only one instance of such vulnerability will be reported. This is useful to "
                "detect situations when multiple .env detectors detect a single file or multiple XSS templates are "
                "triggered on a single page.",
            ] = get_config(
                "NUCLEI_TEMPLATE_GROUPS_FILE",
                default="/opt/artemis/modules/data/nuclei_template_groups.json",
            )

            NUCLEI_MAX_BATCH_SIZE: Annotated[
                int,
                "How many sites to scan at once. This is the maximum batch size - we will try to obtain NUCLEI_MAX_BATCH_SIZE "
                "sites to scan from the queue, but if per-IP locking is enabled, then we will filter ones that are already "
                "scanned by other modules.",
            ] = get_config("NUCLEI_MAX_BATCH_SIZE", default=10, cast=int)

            NUCLEI_TEMPLATES_TO_SKIP: Annotated[
                List[str],
                "Comma-separated list of Nuclei templates not to be executed. See artemis/config.py for the rationale "
                "behind skipping particular templates.",
            ] = get_config(
                "NUCLEI_TEMPLATES_TO_SKIP",
                default=",".join(
                    [
                        # We have a separate module for that, checking whethet the repository is a copy of a public one
                        "http/exposures/configs/exposed-svn.yaml",
                        "http/exposures/configs/git-config.yaml",
                        # We have a separate module checking for a larger number of directory indexes.
                        "http/exposures/configs/configuration-listing.yaml",
                        "http/misconfiguration/sound4-directory-listing.yaml",
                        # The two following templates caused panic: runtime
                        # error: integer divide by zero in github.com/projectdiscovery/retryabledns
                        "dns/azure-takeover-detection.yaml",
                        "dns/elasticbeantalk-takeover.yaml",
                        # This one caused multiple FPs
                        "http/cves/2021/CVE-2021-43798.yaml",
                        # A significant source of false positives
                        "http/exposed-panels/pagespeed-global-admin.yaml",
                        # Admin panel information disclosure - not a high-severity one.
                        "http/cves/2021/CVE-2021-24917.yaml",
                        # caused multiple FPs: travis configuration file provided by a framework without much interesting information.
                        "http/exposures/files/travis-ci-disclosure.yaml",
                        # caused multiple FPs, and as RockMongo is not maintained anymore, let's skip it
                        "http/vulnerabilities/other/rockmongo-xss.yaml",
                        # At CERT.PL we don't report exposed CMS panels, as having them exposed is a standard workflow for small institutions.
                        # Feel free to make a different decision.
                        "http/exposed-panels/adobe/aem-sling-login.yaml",
                        "http/exposed-panels/alfresco-detect.yaml",
                        "http/exposed-panels/backpack/backpack-admin-panel.yaml",
                        "http/exposed-panels/bolt-cms-panel.yaml",
                        "http/exposed-panels/concrete5/concrete5-panel.yaml",
                        "http/exposed-panels/contao-login-panel.yaml",
                        "http/exposed-panels/craftcms-admin-panel.yaml",
                        "http/exposed-panels/django-admin-panel.yaml",
                        "http/exposed-panels/dokuwiki-panel.yaml",
                        "http/exposed-panels/drupal-login.yaml",
                        "http/exposed-panels/ez-publish-panel.yaml",
                        "http/exposed-panels/joomla-panel.yaml",
                        "http/exposed-panels/kentico-login.yaml",
                        "http/exposed-panels/liferay-portal.yaml",
                        "http/exposed-panels/magnolia-panel.yaml",
                        "http/exposed-panels/neos-panel.yaml",
                        "http/exposed-panels/netlify-cms.yaml",
                        "http/exposed-panels/strapi-panel.yaml",
                        "http/exposed-panels/tikiwiki-cms.yaml",
                        "http/exposed-panels/typo3-login.yaml",
                        "http/exposed-panels/umbraco-login.yaml",
                        "http/exposed-panels/wordpress-login.yaml",
                        # At CERT PL we don't report exposed webmails, as it's a standard practice to expose them - feel free to
                        # make different decision.
                        "http/exposed-panels/axigen-webmail.yaml",
                        "http/exposed-panels/squirrelmail-login.yaml",
                        "http/exposed-panels/horde-webmail-login.yaml",
                        "http/exposed-panels/horde-login-panel.yaml",
                        "http/exposed-panels/zimbra-web-login.yaml",
                        "http/exposed-panels/zimbra-web-client.yaml",
                        "http/exposed-panels/icewarp-panel-detect.yaml",
                        # These are Tomcat docs, not application docs
                        "http/exposed-panels/tomcat/tomcat-exposed-docs.yaml",
                        # Generic API docs
                        "http/exposed-panels/arcgis/arcgis-rest-api.yaml",
                        # VPN web portals, SSO and other ones that need to be exposed
                        "http/exposed-panels/fortinet/fortios-panel.yaml",
                        "http/exposed-panels/fortinet/fortinet-fortigate-panel.yaml",
                        "http/exposed-panels/checkpoint/ssl-network-extender.yaml",
                        "http/exposed-panels/pulse-secure-panel.yaml",
                        "http/exposed-panels/pulse-secure-version.yaml",
                        "http/exposed-panels/cisco/cisco-anyconnect-vpn.yaml",
                        "http/exposed-panels/softether-vpn-panel.yaml",
                        "http/exposed-panels/cas-login.yaml",
                        "http/exposed-panels/casdoor-login.yaml",
                        "http/exposed-panels/openam-panel.yaml",
                        "http/exposed-panels/sonicwall-sslvpn-panel.yaml",
                        # Too small impact to report
                        "http/exposed-panels/webeditors-check-detect.yaml",
                        # Online stores, CRMs and ticketing systems - it's a standard practice to have them exposed in a small organization
                        "http/exposed-panels/dynamicweb-panel.yaml",
                        "http/exposed-panels/jira-detect.yaml",
                        "http/exposed-panels/kanboard-login.yaml",
                        "http/exposed-panels/linshare-panel.yaml",
                        "http/exposed-panels/magento-admin-panel.yaml",
                        "http/exposed-panels/mantisbt-panel.yaml",
                        "http/exposed-panels/mautic-crm-panel.yaml",
                        "http/exposed-panels/opencart-panel.yaml",
                        "http/exposed-panels/osticket-panel.yaml",
                        "http/exposed-panels/redmine-panel.yaml",
                        # Mostly meant to be publicly accessible
                        "http/exposed-panels/bigbluebutton-login.yaml",
                        "http/exposed-panels/ilias-panel.yaml",
                        "http/exposed-panels/office-webapps-panel.yaml",
                        "http/exposed-panels/onlyoffice-login-panel.yaml",
                        "http/exposed-panels/opensis-panel.yaml",
                        "http/exposed-panels/projectsend-login.yaml",
                        "http/exposed-panels/rocketchat-panel.yaml",
                        # Source of FPs
                        "custom:CVE-2019-1579",
                        "custom:xss-inside-tag-top-params.yaml",
                        # Nothing particularily interesting
                        "http/miscellaneous/joomla-manifest-file.yaml",
                        "http/exposures/configs/karma-config-js.yaml",
                    ]
                ),
                cast=decouple.Csv(str),
            )

            NUCLEI_ADDITIONAL_TEMPLATES: Annotated[
                List[str],
                "A comma-separated list of Nuclei templates to be used besides the standard list. "
                "vulnerabilities/generic/crlf-injection.yaml was present here but is not anymore due to "
                "a significant number of false positives.",
            ] = get_config(
                "NUCLEI_ADDITIONAL_TEMPLATES",
                default=",".join(
                    [
                        "http/exposures/configs/dompdf-config.yaml",
                        "http/exposures/configs/ftp-credentials-exposure.yaml",
                        "http/exposures/configs/prometheus-metrics.yaml",
                        "http/exposures/files/core-dump.yaml",
                        "http/exposures/files/ds-store-file.yaml",
                        "http/exposures/logs/roundcube-log-disclosure.yaml",
                        "http/miscellaneous/defaced-website-detect.yaml",
                        "http/misconfiguration/django-debug-detect.yaml",
                        "http/misconfiguration/mixed-active-content.yaml",
                        "http/misconfiguration/mysql-history.yaml",
                        "http/misconfiguration/elasticsearch.yaml",
                        "http/misconfiguration/proxy/open-proxy-external.yaml",
                        "http/misconfiguration/server-status-localhost.yaml",
                        "http/misconfiguration/server-status.yaml",
                        "http/misconfiguration/shell-history.yaml",
                        "http/misconfiguration/springboot/springboot-auditevents.yaml",
                        "http/misconfiguration/springboot/springboot-dump.yaml",
                        "http/misconfiguration/springboot/springboot-env.yaml",
                        "http/misconfiguration/springboot/springboot-httptrace.yaml",
                        "http/misconfiguration/springboot/springboot-logfile.yaml",
                        "http/misconfiguration/springboot/springboot-threaddump.yaml",
                        "http/misconfiguration/springboot/springboot-trace.yaml",
                        "http/vulnerabilities/generic/basic-xss-prober.yaml",
                        "http/vulnerabilities/generic/xss-fuzz.yaml",
                    ]
                ),
                cast=decouple.Csv(str),
            )

            NUCLEI_SUSPICIOUS_TEMPLATES: Annotated[
                List[str],
                "A comma-separated list of Nuclei templates to be reviewed manually if found as they "
                "are known to return false positives.",
            ] = get_config(
                "NUCLEI_SUSPICIOUS_TEMPLATES",
                default=",".join(
                    [
                        "custom:xss-inside-tag-top-params",
                        "http/miscellaneous/defaced-website-detect.yaml",
                        "http/misconfiguration/google/insecure-firebase-database.yaml",
                        # Until https://github.com/projectdiscovery/nuclei-templates/issues/8657
                        # gets fixed, these templates return a FP on phpinfo(). Let's not spam
                        # our recipients with FPs.
                        "http/cnvd/2020/CNVD-2020-23735.yaml",
                        "http/vulnerabilities/other/ecshop-sqli.yaml",
                        # Until https://github.com/CERT-Polska/Artemis/issues/899 gets fixed, let's review
                        # these manually.
                        "group:sql-injection",
                    ]
                ),
                cast=decouple.Csv(str),
            )

            NUCLEI_TEMPLATES_TO_RUN_ON_HOMEPAGE_LINKS: Annotated[
                List[str],
                "Normally, Nuclei templates are ran only on the root url. These templates will also run "
                "on all URLs linked from the root URL to detect vulnerabilities on non-root pages.",
            ] = get_config(
                "NUCLEI_TEMPLATES_TO_RUN_ON_HOMEPAGE_LINKS",
                default=",".join(
                    [
                        "http/vulnerabilities/generic/top-xss-params.yaml",
                        "http/vulnerabilities/generic/xss-fuzz.yaml",
                        "http/vulnerabilities/generic/basic-xss-prober.yaml",
                        "http/vulnerabilities/generic/error-based-sql-injection.yaml",
                        "/opt/artemis/modules/data/nuclei_templates_custom/error-based-sql-injection.yaml",
                    ]
                ),
                cast=decouple.Csv(str),
            )

            NUCLEI_MAX_NUM_LINKS_TO_PROCESS: Annotated[
                int,
                "Maximum number of links to be checked with the templates provided in "
                "NUCLEI_TEMPLATES_TO_RUN_ON_HOMEPAGE_LINKS (if more are seen, random "
                "NUCLEI_MAX_NUM_LINKS_TO_PROCESS are chosen).",
            ] = get_config("NUCLEI_MAX_NUM_LINKS_TO_PROCESS", default=100, cast=int)

            NUCLEI_TEMPLATE_CHUNK_SIZE: Annotated[
                int,
                "How big are the chunks to split the template list. E.g. if the template list contains 3000 templates and "
                "NUCLEI_TEMPLATE_CHUNK_SIZE is 1000, three calls will be made with 1000 templates each.",
            ] = get_config("NUCLEI_TEMPLATE_CHUNK_SIZE", default=1000, cast=int)

        class PortScanner:
            PORT_SCANNER_PORT_LIST: Annotated[str, "Chosen list of ports to scan (can be 'short' or 'long')"] = (
                get_config("PORT_SCANNER_PORT_LIST", default="short")
            )

            CUSTOM_PORT_SCANNER_PORTS: Annotated[
                List[int],
                "Custom port list to scan in CSV form (replaces default list).",
            ] = get_config("CUSTOM_PORT_SCANNER_PORTS", default="", cast=decouple.Csv(int))

            PORT_SCANNER_TIMEOUT_MILLISECONDS: Annotated[
                int,
                "Port scanner: milliseconds to wait before timing out",
            ] = get_config("PORT_SCANNER_TIMEOUT_MILLISECONDS", default=5_000, cast=int)

            PORT_SCANNER_MAX_NUM_PORTS: Annotated[
                int,
                "The number of open ports we consider to be too much and a false positive - if we observe more "
                "open ports, we trim by performing an intersection of the result with the list of 100 most popular ones.",
            ] = get_config("PORT_SCANNER_MAX_NUM_PORTS", default=100, cast=int)

        class Postman:
            POSTMAN_MAIL_FROM: Annotated[
                str,
                "Sender e-mail address that will be used to test whether a server is an open relay or allows "
                "sending e-mails to any address.",
            ] = get_config("POSTMAN_MAIL_FROM", default="from@example.com")
            POSTMAN_MAIL_TO: Annotated[
                str,
                "Recipient e-mail address, e.g. for open relay testing.",
            ] = get_config("POSTMAN_MAIL_TO", default="to@example.com")

        class Shodan:
            SHODAN_API_KEY: Annotated[
                str,
                "Shodan API key so that Shodan vulnerabilities will be displayed in Artemis.",
            ] = get_config("SHODAN_API_KEY", default="")

        class SSHBruter:
            ADDITIONAL_BRUTE_FORCE_SLEEP_SECONDS: Annotated[
                int,
                "Some SSH servers drop connections after a large number of tries in a short "
                "time period. This is to combat this behavior.",
            ] = get_config("ADDITIONAL_BRUTE_FORCE_SLEEP_SECONDS", default=20)

        class SubdomainEnumeration:
            RETRIES: Annotated[
                int,
                "Number of retries for subdomain enumeration.",
            ] = get_config("SUBDOMAIN_ENUMERATION_RETRIES", default=10, cast=int)

            SLEEP_TIME_SECONDS: Annotated[
                int,
                "Time to sleep between retries for subdomain enumeration in seconds.",
            ] = get_config("SUBDOMAIN_ENUMERATION_SLEEP_TIME_SECONDS", default=60, cast=int)

            GAU_ADDITIONAL_OPTIONS: Annotated[
                List[str],
                "Additional command-line options that will be passed to gau (https://github.com/lc/gau).",
            ] = get_config(
                "SUBDOMAIN_ENUMERATION_GAU_ADDITIONAL_OPTIONS", default="", cast=decouple.Csv(str, delimiter=" ")
            )

        class VCS:
            VCS_MAX_DB_SIZE_BYTES: Annotated[
                int,
                "Maximum size of the VCS (e.g. SVN) db file.",
            ] = get_config("VCS_MAX_DB_SIZE_BYTES", default=1024 * 1024 * 5, cast=int)

        class WordPressPlugins:
            WORDPRESS_SKIP_VERSION_CHECK_ON_LESS_POPULAR_PLUGINS: Annotated[
                bool,
                "Some plugins have wrong versions in the README. For the most popular 1500 plugins, Artemis team monitors "
                "such cases and excludes the plugins that have wrong versions in the README from scanning. For the less popular "
                "plugins (e.g. if one can be identified by /wp-content/plugins/xyz/ URL in the website source), such "
                "cases can be a source of false positives.\n\n"
                "If this option is set to True, version check for such plugins will not be performed.",
            ] = get_config("WORDPRESS_SKIP_VERSION_CHECK_ON_LESS_POPULAR_PLUGINS", default=False, cast=bool)

        class WordPressScanner:
            WORDPRESS_VERSION_AGE_DAYS: Annotated[
                int,
                "After what number of days we consider the WordPress version to be obsolete. This is a long "
                'threshold because WordPress maintains a separate list of insecure versions, so "old" doesn\'t '
                'mean "insecure" here.',
            ] = get_config("WORDPRESS_VERSION_AGE_DAYS", default=90, cast=int)

        class WordPressBruter:
            WORDPRESS_BRUTER_STRIPPED_PREFIXES: Annotated[
                List[str],
                "Wordpress_bruter extracts the site name to brute-force passwords. For example, if it observes "
                "projectname.example.com it will bruteforce projectname123, projectname2023, ... "
                "This list describes what domain prefixes to strip (e.g. www) so that we bruteforce projectname123, not "
                "www123, when testing www.projectname.example.com.",
            ] = get_config("WORDPRESS_BRUTER_STRIPPED_PREFIXES", default="www", cast=decouple.Csv(str))

        class DomainExpirationScanner:
            DOMAIN_EXPIRATION_TIMEFRAME_DAYS: Annotated[
                int, "The scanner warns if the domain's expiration date falls within this time frame from now."
            ] = get_config("DOMAIN_EXPIRATION_TIMEFRAME_DAYS", default=30, cast=int)

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
