import os
from typing import Annotated, Any, List, Optional, get_type_hints

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
                "AUTOARCHIVER_MIN_AGE_SECONDS", default=120 * 24 * 60 * 60, cast=int
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
        ] = get_config("REPORTING_MAX_VULN_AGE_DAYS", default=120, cast=int)

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
        ] = get_config("MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_LOW", default=18 * 30, cast=int)

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
            when locking is enabled, setting e.g. REQUESTS_PER_SECOND to will cause that no IP receives 2 port
            scanning packets/HTTP requests/MySQL connections/... per second.

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

        QUEUE_LOCATION_MAX_AGE_SECONDS: Annotated[
            int,
            """
            Requires LOCK_SCANNED_TARGETS to be enabled.

            Sometimes the task queue is very long and e.g. the first N tasks can't be taken because they concern IPs that
            are already scanned. To make scanning faster, Artemis remembers the position in the task queue for the next
            QUEUE_LOCATION_MAX_AGE_SECONDS in order not to repeat trying to lock the first tasks in the queue.
            """,
        ] = get_config("QUEUE_LOCATION_MAX_AGE_SECONDS", default=900, cast=int)

        SCAN_DESTINATION_LOCK_MAX_TRIES: Annotated[
            int,
            """
            Requires LOCK_SCANNED_TARGETS to be enabled.

            Amount of times module will try to get a lock on scanned destination (with sleeps inbetween)
            before rescheduling task for later.
            """,
        ] = get_config("SCAN_DESTINATION_LOCK_MAX_TRIES", default=2, cast=int)

    class PublicSuffixes:
        ALLOW_SUBDOMAIN_ENUMERATION_IN_PUBLIC_SUFFIXES: Annotated[
            bool,
            "Whether we will enumerate subdomains for a public suffix (e.g. .pl) if it appears on the target list. This may cause very large "
            "number of domains to be scanned.",
        ] = get_config("ALLOW_SUBDOMAIN_ENUMERATION_IN_PUBLIC_SUFFIXES", default=False, cast=bool)

        ADDITIONAL_PUBLIC_SUFFIXES: Annotated[
            List[str],
            "Additional domains that will be treated as public suffixes (even though they're not on the default Public Suffix List).",
        ] = get_config("ADDITIONAL_PUBLIC_SUFFIXES", default="", cast=decouple.Csv(str))

    class Limits:
        TASK_TIMEOUT_SECONDS: Annotated[int, "What is the maximum task run time (after which it will get killed)."] = (
            get_config("TASK_TIMEOUT_SECONDS", default=12 * 3600, cast=int)
        )

        REQUEST_TIMEOUT_SECONDS: Annotated[
            int,
            "Default request timeout (for all protocols).",
        ] = get_config("REQUEST_TIMEOUT_SECONDS", default=5, cast=int)

        SCAN_SPEED_OVERRIDES_FILE: Annotated[
            Optional[str],
            "A JSON file with a dictionary mapping from IP to scan speed - use if you want to slow down scanning of particular hosts.",
        ] = get_config("SCAN_SPEED_OVERRIDES_FILE", default="", cast=str)

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

        STOP_SCANNING_MODULES_IF_FREE_DISK_SPACE_LOWER_THAN_MB: Annotated[
            int,
            "If free disk space on / becomes lower than this value, scanning will stop so that we don't end up being unable to save the results.",
        ] = get_config("STOP_SCANNING_MODULES_IF_FREE_DISK_SPACE_LOWER_THAN_MB", default=1000)

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
        ] = get_config("MAX_NUM_TASKS_TO_PROCESS", default=1000, cast=int)

        CONTENT_PREFIX_SIZE: Annotated[
            int,
            "In order not to overload the DB and bandwidth, this determines how long the downloaded content would be (in bytes).",
        ] = get_config("CONTENT_PREFIX_SIZE", default=1024 * 100, cast=int)

        MODULES_DISABLED_BY_DEFAULT: Annotated[
            List[str],
            "Artemis modules that are disabled by default (but may easily be enabled in the UI)",
        ] = get_config(
            "MODULES_DISABLED_BY_DEFAULT", default="example,humble,ssh_bruter", cast=decouple.Csv(str, delimiter=",")
        )

        SUBDOMAIN_ENUMERATION_TTL_DAYS: Annotated[
            int,
            "If we request a domain for subdomain enumeration, we will save that it has already been enumerated, so that e.g. "
            "if we requested crtsh enumeration on example.com and received www.example.com, crtsh enumeration on www.example.com won't happen "
            "in SUBDOMAIN_ENUMERATION_TTL_DAYS days. This is the TTL of such markers.",
        ] = get_config("SUBDOMAIN_ENUMERATION_TTL_DAYS", default=10, cast=int)

        ADDITIONAL_HOSTS_FILE_PATH: Annotated[str, "File that will be appended to /etc/hosts"] = get_config(
            "ADDITIONAL_HOSTS_FILE_PATH", default="", cast=str
        )

        MAX_URLS_TO_SCAN: Annotated[
            int,
            "Maximum number of URLs to scan per target for modules that crawl like lfi_detector, Nuclei, sq_injection_detector, etc.",
        ] = get_config("MAX_URLS_TO_SCAN", default=25, cast=int)

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
            NUCLEI_TEMPLATE_LISTS: Annotated[
                str,
                "Which template lists to use. Available: known_exploited_vulnerabilities (from https://github.com/Ostorlab/KEV/), "
                "critical (having severity=critical), high (having severity=high), medium (having severity=medium), "
                "log_exposures (http/exposures/logs folder in https://github.com/projectdiscovery/nuclei-templates/), "
                "exposed_panels (http/exposed-panels/ folder).",
            ] = get_config(
                "NUCLEI_TEMPLATE_LISTS",
                default="known_exploited_vulnerabilities,critical,high,log_exposures,exposed_panels",
                cast=decouple.Csv(str, delimiter=","),
            )

            NUCLEI_INTERACTSH_SERVER: Annotated[
                str,
                "Which interactsh server to use. if None, uses the default.",
            ] = get_config("NUCLEI_INTERACTSH_SERVER", default=None, cast=str)

            NUCLEI_CHECK_TEMPLATE_LIST: Annotated[
                bool,
                "Whether to check that the downloaded Nuclei template list is not empty (may fail e.g. on Github CI "
                "when the Github API rate limits are spent).",
            ] = get_config("NUCLEI_CHECK_TEMPLATE_LIST", default=True, cast=bool)

            NUCLEI_SECONDS_PER_REQUEST_ON_RETRY: Annotated[
                bool,
                "When retrying due to 'context deadline exceeded', each request will take at least max(2 * SECONDS_PER_REQUEST, "
                "NUCLEI_SECONDS_PER_REQUEST_ON_RETRY).",
            ] = get_config("NUCLEI_SECONDS_PER_REQUEST_ON_RETRY", default=0.1, cast=float)

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
                        "http/exposures/files/svn-wc-db.yaml",
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
                        "http/exposed-panels/fortinet/fortiweb-panel.yaml",
                        "http/exposed-panels/fortinet/fortios-panel.yaml",
                        "http/exposed-panels/fortinet/fortinet-fortigate-panel.yaml",
                        "http/exposed-panels/checkpoint/ssl-network-extender.yaml",
                        "http/exposed-panels/pulse-secure-panel.yaml",
                        "http/exposed-panels/pulse-secure-version.yaml",
                        "http/exposed-panels/cisco/cisco-asa-panel.yaml",
                        "http/exposed-panels/cisco/cisco-anyconnect-vpn.yaml",
                        "http/exposed-panels/openvpn-connect.yaml",
                        "http/exposed-panels/ivanti-csa-panel.yaml",
                        "http/exposed-panels/ivanti-connect-secure-panel.yaml",
                        "http/exposed-panels/softether-vpn-panel.yaml",
                        "http/exposed-panels/cas-login.yaml",
                        "http/exposed-panels/casdoor-login.yaml",
                        "http/exposed-panels/openam-panel.yaml",
                        "http/exposed-panels/sonicwall-sslvpn-panel.yaml",
                        # Too small impact to report
                        "http/exposed-panels/webeditors-check-detect.yaml",
                        # Online stores, CRMs and ticketing systems - it's a standard practice to have them exposed in a small organization
                        "http/exposed-panels/bitrix-panel.yaml",
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
                        "http/exposed-panels/librespeed-panel.yaml",
                        "http/exposed-panels/office-webapps-panel.yaml",
                        "http/exposed-panels/onlyoffice-login-panel.yaml",
                        "http/exposed-panels/opensis-panel.yaml",
                        "http/exposed-panels/projectsend-login.yaml",
                        "http/exposed-panels/rocketchat-panel.yaml",
                        # Source of FPs
                        "custom:CVE-2019-1579",
                        "custom:CVE-2024-35286",
                        "custom:CVE-2022-43939",
                        "custom:CVE-2025-24016",
                        "custom:xss-inside-tag-top-params.yaml",
                        # Nothing particularily interesting
                        "http/exposures/apis/drupal-jsonapi-user-listing.yaml",
                        "http/miscellaneous/joomla-manifest-file.yaml",
                        "http/exposures/configs/karma-config-js.yaml",
                        "http/cves/2000/CVE-2000-0114.yaml",
                        # From the message: "there is no common path to exploit that has a user impact."
                        "http/cves/2021/CVE-2021-20323.yaml",
                        # This is Open Redirect in Host header, not exploitable in standard conditions. Besides, this is disputed by vendor.
                        "http/cves/2023/CVE-2023-24044.yaml",
                        # Open Redirect in Referer, X-Forwarded-Host or another header making it hard to exploit
                        "http/vulnerabilities/wordpress/music-store-open-redirect.yaml",
                        "http/cves/2020/CVE-2020-15129.yaml",
                        "http/cves/2021/CVE-2021-44528.yaml",
                        # Minor information leaks
                        "http/cves/2017/CVE-2017-5487.yaml",
                        "http/cves/2019/CVE-2019-8449.yaml",
                        "http/cves/2020/CVE-2020-14179.yaml",
                        "http/cves/2020/CVE-2020-14181.yaml",
                        "http/cves/2021/CVE-2021-3293.yaml",
                        "http/cves/2021/CVE-2021-25118.yaml",
                        "http/cves/2021/CVE-2021-44848.yaml",
                        "http/cves/2023/CVE-2023-4568.yaml",
                        "http/cves/2024/CVE-2024-1208.yaml",
                        "http/cves/2024/CVE-2024-1210.yaml",
                        "http/cves/2024/CVE-2024-3097.yaml",
                        # Over 50 requests
                        "http/cves/2017/CVE-2017-17562.yaml",
                        "http/cves/2019/CVE-2019-17382.yaml",
                        "http/cves/2022/CVE-2022-2034.yaml",
                        "http/cves/2023/CVE-2023-24489.yaml",
                        "http/default-logins/apache/tomcat-default-login.yaml",
                        "http/default-logins/oracle/peoplesoft-default-login.yaml",
                        "http/exposed-panels/adminer-panel-detect.yaml",
                        "http/exposures/apis/swagger-api.yaml",
                        "http/exposures/backups/php-backup-files.yaml",
                        "http/exposures/backups/zip-backup-files.yaml",
                        "http/exposures/files/generic-db.yaml",
                        "http/fuzzing/cache-poisoning-fuzz.yaml",
                        "http/fuzzing/header-command-injection.yaml",
                        "http/fuzzing/mdb-database-file.yaml",
                        "http/fuzzing/prestashop-module-fuzz.yaml",
                        "http/fuzzing/waf-fuzz.yaml",
                        "http/fuzzing/wordpress-plugins-detect.yaml",
                        "http/fuzzing/wordpress-themes-detect.yaml",
                        "http/fuzzing/wordpress-weak-credentials.yaml",
                        "http/miscellaneous/defacement-detect.yaml",
                        "http/misconfiguration/aem/aem-default-get-servlet.yaml",
                        "http/misconfiguration/akamai/akamai-s3-cache-poisoning.yaml",
                        "http/misconfiguration/gitlab/gitlab-api-user-enum.yaml",
                        "http/misconfiguration/gitlab/gitlab-user-enum.yaml",
                        "http/misconfiguration/servicenow-widget-misconfig.yaml",
                        "http/technologies/graphql-detect.yaml",
                        "http/technologies/graylog/graylog-api-exposure.yaml",
                        "http/vulnerabilities/apache/shiro/shiro-deserialization-detection.yaml",
                        "http/vulnerabilities/generic/open-redirect-generic.yaml",
                        "http/vulnerabilities/grafana/grafana-file-read.yaml",
                        "http/vulnerabilities/tongda/tongda-auth-bypass.yaml",
                        "http/vulnerabilities/wordpress/wp-xmlrpc-brute-force.yaml",
                        "javascript/default-logins/ssh-default-logins.yaml",
                        # Mostly Moodle config
                        "http/exposures/configs/behat-config.yaml",
                        # Catches multiple open redirects, replaced with artemis/modules/data/nuclei_templates_custom/open-redirect-simplified.yaml
                        "http/cves/2018/CVE-2018-11784.yaml",
                        "http/cves/2019/CVE-2019-10098.yaml",
                        "http/cves/2022/CVE-2022-28923.yaml",
                        # Too many FPs
                        "http/cves/2020/CVE-2020-2096.yaml",
                        "http/cves/2023/CVE-2023-35160.yaml",
                        "http/cves/2023/CVE-2023-35161.yaml",
                        "http/cves/2023/CVE-2023-35162.yaml",
                        "http/exposed-panels/fireware-xtm-user-authentication.yaml",
                        # Popular configuration
                        "network/default-login/ftp-anonymous-login.yaml",
                        # Will be enabled back after fixing a bug: https://github.com/projectdiscovery/nuclei-templates/pull/10998
                        "http/fuzzing/xff-403-bypass.yaml",
                        # Not that severe to spam people
                        "javascript/cves/2023/CVE-2023-48795.yaml",
                        "http/cves/2024/CVE-2024-43919.yaml",
                        # We already check for Gitlab
                        "http/exposed-panels/ghe-encrypt-saml.yaml",
                    ]
                ),
                cast=decouple.Csv(str),
            )

            NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY_FILE: Annotated[
                str,
                "File with a list of Nuclei templates (one per line) to be skipped with NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY_PROBABILITY "
                "probability. Use this if you have some templates that never yield results - you don't want to skip them altogether (because "
                "they may start giving results) but maybe don't run them on all hosts.",
            ] = get_config(
                "NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY_FILE",
                default="",
                cast=str,
            )

            NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY_PROBABILITY: Annotated[
                float,
                "Probability (0...100) of each template from NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY to be skipped. "
                "Use this if you have some templates that never yield results - you don't want to skip them altogether (because "
                "they may start giving results) but maybe don't run them on all hosts.",
            ] = get_config(
                "NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY_PROBABILITY",
                default=0,
                cast=float,
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
                        "network/detection/rtsp-detect.yaml",
                        "http/miscellaneous/defaced-website-detect.yaml",
                        "http/misconfiguration/directory-listing-no-host-header.yaml",
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
                        "custom:error-based-sql-injection",
                        "http/miscellaneous/defaced-website-detect.yaml",
                        "http/misconfiguration/google/insecure-firebase-database.yaml",
                        "custom:CVE-2024-4836",
                        "custom:CVE-2024-35286",
                        # Until https://github.com/projectdiscovery/nuclei-templates/issues/8657
                        # gets fixed, these templates return a FP on phpinfo(). Let's not spam
                        # our recipients with FPs.
                        "http/cnvd/2020/CNVD-2020-23735.yaml",
                        "http/vulnerabilities/other/ecshop-sqli.yaml",
                        # Until https://github.com/CERT-Polska/Artemis/issues/899 gets fixed, let's review
                        # these manually.
                        "group:sql-injection",
                        # Sometimes a source of FPs or true positives with misidentified software name
                        "custom:CVE-2019-18935",
                        "http/cves/2005/CVE-2005-4385.yaml",
                        "http/cves/2007/CVE-2007-0885.yaml",
                        "http/cves/2008/CVE-2008-2398.yaml",
                        "http/cves/2009/CVE-2009-1872.yaml",
                        "http/cves/2010/CVE-2010-2307.yaml",
                        "http/cves/2010/CVE-2010-4231.yaml",
                        "http/cves/2011/CVE-2011-5106.yaml",
                        "http/cves/2012/CVE-2012-4547.yaml",
                        "http/cves/2012/CVE-2012-4889.yaml",
                        "http/cves/2014/CVE-2014-2908.yaml",
                        "http/cves/2014/CVE-2014-9444.yaml",
                        "http/cves/2015/CVE-2015-3035.yaml",
                        "http/cves/2015/CVE-2015-5354.yaml",
                        "http/cves/2018/CVE-2018-6184.yaml",
                        "http/cves/2015/CVE-2015-8349.yaml",
                        "http/cves/2016/CVE-2016-7981.yaml",
                        "http/cves/2016/CVE-2016-8527.yaml",
                        "http/cves/2017/CVE-2017-12794.yaml",
                        "http/cves/2018/CVE-2018-8006.yaml",
                        "http/cves/2018/CVE-2018-10956.yaml",
                        "http/cves/2018/CVE-2018-11709.yaml",
                        "http/cves/2018/CVE-2018-12095.yaml",
                        "http/cves/2018/CVE-2018-12998.yaml",
                        "http/cves/2018/CVE-2018-13380.yaml",
                        "http/cves/2018/CVE-2018-14013.yaml",
                        "http/cves/2018/CVE-2018-16836.yaml",
                        "http/cves/2018/CVE-2018-18570.yaml",
                        "http/cves/2019/CVE-2019-10098.yaml",
                        "http/cves/2019/CVE-2019-18922.yaml",
                        "http/cves/2019/CVE-2019-3911.yaml",
                        "http/cves/2019/CVE-2019-7219.yaml",
                        "http/cves/2019/CVE-2019-7315.yaml",
                        "http/cves/2019/CVE-2019-7543.yaml",
                        "http/cves/2019/CVE-2019-10475.yaml",
                        "http/cves/2019/CVE-2019-11510.yaml",
                        "http/cves/2019/CVE-2019-12461.yaml",
                        "http/cves/2019/CVE-2019-13392.yaml",
                        "http/cves/2020/CVE-2020-1943.yaml",
                        "http/cves/2020/CVE-2020-2140.yaml",
                        "http/cves/2020/CVE-2020-6171.yaml",
                        "http/cves/2020/CVE-2020-15500.yaml",
                        "http/cves/2020/CVE-2020-19282.yaml",
                        "http/cves/2020/CVE-2020-19283.yaml",
                        "http/cves/2020/CVE-2020-27982.yaml",
                        "http/cves/2020/CVE-2020-35774.yaml",
                        "http/cves/2020/CVE-2020-35848.yaml",
                        "http/cves/2021/CVE-2021-3654.yaml",
                        "http/cves/2021/CVE-2021-24288.yaml",
                        "http/cves/2021/CVE-2021-24389.yaml",
                        "http/cves/2021/CVE-2021-24838.yaml",
                        "http/cves/2021/CVE-2021-26702.yaml",
                        "http/cves/2021/CVE-2021-26710.yaml",
                        "http/cves/2021/CVE-2021-26723.yaml",
                        "http/cves/2021/CVE-2021-29625.yaml",
                        "http/cves/2021/CVE-2021-30049.yaml",
                        "http/cves/2021/CVE-2021-30213.yaml",
                        "http/cves/2021/CVE-2021-31250.yaml",
                        "http/cves/2021/CVE-2021-38702.yaml",
                        "http/cves/2021/CVE-2021-40868.yaml",
                        "http/cves/2021/CVE-2021-40960.yaml",
                        "http/cves/2021/CVE-2021-40978.yaml",
                        "http/cves/2021/CVE-2021-41467.yaml",
                        "http/cves/2021/CVE-2021-41773.yaml",
                        "http/cves/2021/CVE-2021-42565.yaml",
                        "http/cves/2021/CVE-2021-42566.yaml",
                        "http/cves/2021/CVE-2021-43831.yaml",
                        "http/cves/2021/CVE-2021-45380.yaml",
                        "http/cves/2023/CVE-2023-35161.yaml",
                        "http/cves/2023/CVE-2023-39650.yaml",
                        "http/cves/2023/CVE-2023-43373.yaml",
                        "http/cves/2023/CVE-2023-43374.yaml",
                        "http/cves/2023/CVE-2023-47684.yaml",
                        "http/iot/targa-camera-lfi.yaml",
                        "http/vulnerabilities/ibm/eclipse-help-system-xss.yaml",
                        "http/vulnerabilities/ibm/ibm-infoprint-lfi.yaml",
                        "http/vulnerabilities/other/bullwark-momentum-lfi.yaml",
                        "http/vulnerabilities/other/discourse-xss.yaml",
                        "http/vulnerabilities/ibm/eclipse-help-system-xss.yaml",
                        "http/vulnerabilities/other/global-domains-xss.yaml",
                        "http/vulnerabilities/other/homeautomation-v3-openredirect.yaml",
                        "http/vulnerabilities/other/magicflow-lfi.yaml",
                        "http/vulnerabilities/other/java-melody-xss.yaml",
                        "http/vulnerabilities/moodle/moodle-filter-jmol-xss.yaml",
                        "http/vulnerabilities/other/nginx-merge-slashes-path-traversal.yaml",
                        "http/vulnerabilities/other/parentlink-xss.yaml",
                        "http/vulnerabilities/other/processmaker-lfi.yaml",
                        "http/vulnerabilities/other/sick-beard-xss.yaml",
                        "http/vulnerabilities/squirrelmail/squirrelmail-add-xss.yaml",
                        "http/vulnerabilities/other/gsoap-lfi.yaml",
                        "http/vulnerabilities/other/turbocrm-xss.yaml",
                        "http/vulnerabilities/other/wems-manager-xss.yaml",
                        "http/vulnerabilities/wordpress/wp-touch-redirect.yaml",
                        "http/fuzzing/iis-shortname.yaml",
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
                        "http/fuzzing/linux-lfi-fuzzing.yaml",
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
            ] = get_config("NUCLEI_MAX_NUM_LINKS_TO_PROCESS", default=20, cast=int)

            NUCLEI_CHUNK_SIZE: Annotated[
                int,
                "How big are the chunks to split the template/workflow list. E.g. if the template list contains 600 templates and "
                "NUCLEI_CHUNK_SIZE is 200, three calls will be made with 200 templates each.",
            ] = get_config("NUCLEI_CHUNK_SIZE", default=200, cast=int)

        class PlaceholderPageContent:
            ENABLE_PLACEHOLDER_PAGE_DETECTOR: Annotated[
                bool,
                "Enable or disable placeholder pages detector. Using this feature you may skip vulnerability scanning "
                "for websites that aren't built yet, but e.g. contain a hosting provider placeholder page. "
                "If the page exists and the specified string is found within it, the page will not be scanned for "
                "vulnerabilities. If the page is not marked as a placeholder, a full scan will be performed.",
            ] = get_config(
                "ENABLE_PLACEHOLDER_PAGE_DETECTOR",
                default=False,
                cast=bool,
            )
            PLACEHOLDER_PAGE_CONTENT_FILENAME: Annotated[
                str,
                "Path to placeholder page content file. The file is divided into lines – each line is a string "
                "containing a different HTML code element to check.",
            ] = get_config(
                "PLACEHOLDER_PAGE_CONTENT_FILENAME",
                default="/opt/artemis/modules/data/placeholder_page_content.txt",
                cast=str,
            )

        class PortScanner:
            PORT_SCANNER_PORT_LIST: Annotated[str, "Chosen list of ports to scan (can be 'short' or 'long')"] = (
                get_config("PORT_SCANNER_PORT_LIST", default="short")
            )

            CUSTOM_PORT_SCANNER_PORTS: Annotated[
                List[int],
                "Custom port list to scan in CSV form (replaces default list).",
            ] = get_config("CUSTOM_PORT_SCANNER_PORTS", default="", cast=decouple.Csv(int))

            ADD_PORTS_FROM_SHODAN_INTERNETDB: Annotated[
                bool,
                "Besides the scanned ports (configured by PORT_SCANNER_PORT_LIST and CUSTOM_PORT_SCANNER_PORTS), "
                "add ports from internetdb.shodan.io. "
                "By using this source you confirm that you have read carefully the terms and conditions on "
                "https://internetdb.shodan.io/ and agree to respect them, in particular in ensuring no conflict "
                "with the commercialization clause. For the avoidance of doubt, in any case, you remain solely "
                "liable for how you use this source and your compliance with the terms, and NASK is relieved of "
                "such liability to the fullest extent possible.",
            ] = get_config("ADD_PORTS_FROM_SHODAN_INTERNETDB", default=False, cast=bool)

            PORT_SCANNER_TIMEOUT_MILLISECONDS: Annotated[
                int,
                "Port scanner: milliseconds to wait before timing out",
            ] = get_config("PORT_SCANNER_TIMEOUT_MILLISECONDS", default=5_000, cast=int)

            PORT_SCANNER_MAX_BATCH_SIZE: Annotated[
                int,
                "Port scanner: number of hosts scanned by one port_scanner instance",
            ] = get_config("PORT_SCANNER_MAX_BATCH_SIZE", default=10, cast=int)

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

        class RemovedDomainExistingVhost:
            REMOVED_DOMAIN_EXISTING_VHOST_PASSIVEDNS_URLS: Annotated[
                str,
                "Comma-separated list of URLs (optionally with username:password) to download old domain IPs from. "
                "Currently, the system was tested with circl.lu passive DNS. **The URL should end with /pdns/query/**.",
            ] = get_config("REMOVED_DOMAIN_EXISTING_VHOST_PASSIVEDNS_URLS", default=None, cast=decouple.Csv(str))

            REMOVED_DOMAIN_EXISTING_VHOST_REPORT_ONLY_SUBDOMAINS: Annotated[
                str,
                "If set to True, 'removed domain but existing vhost' situations will be reported only for subdomains.",
            ] = get_config("REMOVED_DOMAIN_EXISTING_VHOST_REPORT_ONLY_SUBDOMAINS", default=False, cast=bool)

            REMOVED_DOMAIN_EXISTING_VHOST_PASSIVEDNS_SLEEP_BETWEEN_REQUESTS_SECONDS: Annotated[
                float,
                "How long to sleep between passivedns requests in order not to overload the provider.",
            ] = get_config(
                "REMOVED_DOMAIN_EXISTING_VHOST_PASSIVEDNS_SLEEP_BETWEEN_REQUESTS_SECONDS", default=10, cast=float
            )

            REMOVED_DOMAIN_EXISTING_VHOST_SIMILARITY_THRESHOLD: Annotated[
                float,
                "How similar the results for correct and different domain should be to consider that the server "
                "doesn't host the given domain.",
            ] = get_config("REMOVED_DOMAIN_EXISTING_VHOST_SIMILARITY_THRESHOLD", default=0.5, cast=float)

        class ReverseDNSLookup:
            REVERSE_DNS_APIS: Annotated[
                List[str],
                "List of URLs (such as e.g. https://internetdb.shodan.io/) that provide a JSON dictionary with 'hostnames' field for an IP. "
                "By using this source you confirm that you have read carefully the terms and conditions on "
                "https://internetdb.shodan.io/ and agree to respect them, in particular in ensuring no conflict "
                "with the commercialization clause. For the avoidance of doubt, in any case, you remain solely "
                "liable for how you use this source and your compliance with the terms, and NASK is relieved of "
                "such liability to the fullest extent possible.",
            ] = get_config("REVERSE_DNS_APIS", default="", cast=decouple.Csv(str))

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

            DNS_BRUTE_FORCE_TIME_LIMIT_SECONDS: Annotated[
                int,
                "Time limit for DNS brute force in seconds - some of the servers are very slow, so we don't want to wait too long.",
            ] = get_config("DNS_BRUTE_FORCE_TIME_LIMIT_SECONDS", default=1200, cast=int)

            DNS_QUERIES_PER_SECOND: Annotated[
                int,
                "Number of DNS queries per second (as they are easier to handle than e.g. HTTP queries, let's have a separate limit)",
            ] = get_config("DNS_QUERIES_PER_SECOND", default=20, cast=int)

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

        class SqlInjectionDetector:
            SQL_INJECTION_STOP_ON_FIRST_MATCH: Annotated[
                bool,
                "Whether to display only the first SQL injection and stop scanning.",
            ] = get_config("SQL_INJECTION_STOP_ON_FIRST_MATCH", default=True, cast=bool)
            SQL_INJECTION_NUM_RETRIES_TIME_BASED: Annotated[
                int,
                "How many times to re-check whether long request duration with inject (and short without inject) is indeed a vulnerability or a random fluctuation ",
            ] = get_config("SQL_INJECTION_NUM_RETRIES_TIME_BASED", default=10, cast=int)
            SQL_INJECTION_TIME_THRESHOLD: Annotated[
                int,
                "Seconds to sleep using the sleep() or pg_sleep() methods",
            ] = get_config("SQL_INJECTION_TIME_THRESHOLD", default=5, cast=int)

        class LFIDetector:
            LFI_STOP_ON_FIRST_MATCH: Annotated[
                bool,
                "Whether to display only the first LFI and stop scanning.",
            ] = get_config("LFI_STOP_ON_FIRST_MATCH", default=True, cast=bool)

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
