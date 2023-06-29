import decouple
from redis import Redis


class Config:
    # Connection string to the MongoDB database
    DB_CONN_STR = decouple.config("DB_CONN_STR", default="")

    # Connection string to Redis store
    REDIS_CONN_STR = decouple.config("REDIS_CONN_STR")

    # An already constructed Redis client
    REDIS = Redis.from_url(decouple.config("REDIS_CONN_STR"))

    # Custom User-Agent string used by Artemis (if not set, the tool defaults will be used: requests, Nuclei etc.)
    CUSTOM_USER_AGENT = decouple.config("CUSTOM_USER_AGENT", default="")

    # When creating e-mail reports, what is the vulnerability maximum age (in days) for it to be reported
    REPORTING_MAX_VULN_AGE_DAYS = decouple.config("REPORTING_MAX_VULN_AGE_DAYS", default=14, cast=int)

    # If a report has already been seen earlier - how much time needs to pass for a second e-mail to be sent
    MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_LOW = decouple.config(
        "MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_LOW", default=6 * 30, cast=int
    )
    MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_MEDIUM = decouple.config(
        "MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_MEDIUM", default=3 * 30, cast=int
    )
    MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_HIGH = decouple.config(
        "MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_HIGH", default=14, cast=int
    )

    # Whether we will scan a public suffix (e.g. .pl) if it appears on the target list. This may cause very large
    # number of domains to be scanned.
    ALLOW_SCANNING_PUBLIC_SUFFIXES = decouple.config("ALLOW_SCANNING_PUBLIC_SUFFIXES", default=False, cast=bool)

    # additional domains that will be treated as public suffixes (even though they're not on the default Public Suffix List)
    ADDITIONAL_PUBLIC_SUFFIXES = decouple.config("ADDITIONAL_PUBLIC_SUFFIXES", default="", cast=decouple.Csv(str))

    # What is the maximum task run time (after which it will get killed)
    TASK_TIMEOUT_SECONDS = 4 * 3600

    # After this number of tasks, the service will get restarted. This is to prevent
    # situations such as slow memory leaks.
    MAX_NUM_TASKS_TO_PROCESS = 1000

    # By default, Artemis will check whether the reverse DNS lookup for an IP matches
    # the original domain. For example, if we encounter the 1.1.1.1 ip which resolves to
    # new.example.com, Artemis will check whether it is a subdomain of the original task
    # domain.
    #
    # This is to prevent Artemis from randomly walking through the internet after encountering
    # a misconfigured Reverse DNS record (e.g. pointing to a completely different domain).
    #
    # The downside of that is that when you don't provide original domain (e.g. provide
    # an IP to be scanned), the domain from the reverse DNS lookup won't be scanned. Therefore this
    # behavior is configurable and may be turned off.
    VERIFY_REVDNS_IN_SCOPE = decouple.config("VERIFY_REVDNS_IN_SCOPE", default=True, cast=bool)

    # What paths to skip in the robots and directory_index modules
    NOT_INTERESTING_PATHS = decouple.config("NOT_INTERESTING_PATHS", default="/icon/,/icons/", cast=decouple.Csv(str))

    # default request timeout (for all protocols)
    REQUEST_TIMEOUT_SECONDS = decouple.config("REQUEST_TIMEOUT_SECONDS", default=10, cast=int)

    # Ports that we will treat as "standard http/https ports" when deduplicating vulnerabilities - that is,
    # if we observe identical vulnerability of two standard ports (e.g. on 80 and on 443), we will treat
    # such case as the same vulnerability.
    #
    # This is configurable because e.g. we observed some hostings serving mirrors of content from
    # port 80 on ports 81-84.
    REPORTER_DEDUPLICATION_COMMON_HTTP_PORTS = decouple.config(
        "REPORTER_DEDUPLICATION_COMMON_HTTP_PORTS", default="80,443", cast=decouple.Csv(int)
    )

    # == Rate limit settings
    # Due to the way this behavior is implemented, we cannot guarantee that a host will never receive more than X
    # requests per second.

    # E.g. when set to 2, Artemis will strive to make no more than one HTTP/MySQL connect/... request per two seconds for any host.
    SECONDS_PER_REQUEST_FOR_ONE_IP = decouple.config("SECONDS_PER_REQUEST_FOR_ONE_IP", default=0, cast=int)

    # E.g. when set to 100, Artemis will strive to send no more than 100 port scanning packets per seconds to any host.
    SCANNING_PACKETS_PER_SECOND_PER_IP = decouple.config("SCANNING_PACKETS_PER_SECOND_PER_IP", default=100, cast=int)

    # Whether Artemis should strive to make at most one module scan a target at a given time
    LOCK_SCANNED_TARGETS = decouple.config("LOCK_SCANNED_TARGETS", default=False, cast=bool)

    # When a resource is locked using artemis.resource_lock.ResourceLock, a retry will be performed in the
    # next LOCK_SLEEP_MIN_SECONDS..LOCK_SLEEP_MAX_SECONDS seconds.
    LOCK_SLEEP_MIN_SECONDS = decouple.config("LOCK_SLEEP_MIN_SECONDS", default=0.1, cast=float)
    LOCK_SLEEP_MAX_SECONDS = decouple.config("LOCK_SLEEP_MAX_SECONDS", default=0.5, cast=float)

    # Amount of times module will try to get a lock on scanned destination (with sleeps inbetween)
    # before rescheduling task for later.
    SCAN_DESTINATION_LOCK_MAX_TRIES = decouple.config("SCAN_DESTINATION_LOCK_MAX_TRIES", default=2, cast=int)

    # Locks are not permanent, because a service that has acquired a lock may get restarted or killed.
    # This is the lock default expiry time.
    DEFAULT_LOCK_EXPIRY_SECONDS = decouple.config("DEFAULT_LOCK_EXPIRY_SECONDS", default=3600, cast=int)

    # In order not to overload the DB and bandwidth, this determines how long
    # the downloaded content would be (in bytes).
    CONTENT_PREFIX_SIZE = decouple.config("CONTENT_PREFIX_SIZE", default=10240, cast=int)

    # == bruter settings (artemis/modules/bruter.py)
    # A threshold in case bruter finds too many files on a server
    # and we want to skip this as a false positive. 0.1 means 10%.
    BRUTER_FALSE_POSITIVE_THRESHOLD = 0.1

    # If set to True, bruter will follow redirects. If to False, a redirect will be interpreted that a URL
    # doesn't exist, thus decreasing the number of false positives at the cost of losing some true positives.
    BRUTER_FOLLOW_REDIRECTS = decouple.config("BRUTER_FOLLOW_REDIRECTS", default=True, cast=bool)

    # == crtsh settings (artemis/modules/crtsh.py)
    # How many times should we try to obtain subdomains list
    CRTSH_NUM_RETRIES = decouple.config("CRTSH_NUM_RETRIES", default=10, cast=int)
    # How long to sleep between tries
    CRTSH_SLEEP_ON_RETRY_SECONDS = decouple.config("CRTSH_SLEEP_ON_RETRY_SECONDS", default=30, cast=int)

    # == dns_scanner reporting settings (artemis/reporting/modules/dns_scanner.py)
    # The number of domains below which zone transfer won't be reported
    ZONE_TRANSFER_SIZE_REPORTING_THRESHOLD = decouple.config(
        "ZONE_TRANSFER_SIZE_REPORTING_THRESHOLD", cast=int, default=2
    )

    # == gau settings (artemis/modules/gau.py)
    # custom port list to scan in CSV form (replaces default list)
    GAU_ADDITIONAL_OPTIONS = decouple.config(
        "GAU_ADDITIONAL_OPTIONS", default="", cast=decouple.Csv(str, delimiter=" ")
    )

    # == joomla_scanner settings (artemis/modules/joomla_scanner.py)
    # After what number of days we consider the Joomla version to be obsolete
    JOOMLA_VERSION_AGE_DAYS = decouple.config("JOOMLA_VERSION_AGE_DAYS", default=30, cast=int)

    # == nuclei settings (artemis/modules/nuclei.py)
    # whether to check that the downloaded Nuclei template list is not empty (may fail e.g. on Github CI when the
    # Github API rate limits are spent)
    NUCLEI_CHECK_TEMPLATE_LIST = decouple.config("NUCLEI_CHECK_TEMPLATE_LIST", default=True, cast=bool)

    NUCLEI_TEMPLATES_TO_SKIP = decouple.config(
        "NUCLEI_TEMPLATES_TO_SKIP",
        default=",".join(
            [
                # The two following templates caused panic: runtime
                # error: integer divide by zero in github.com/projectdiscovery/retryabledns
                "dns/azure-takeover-detection.yaml",
                "dns/elasticbeantalk-takeover.yaml",
                # This one caused multiple FPs
                "http/cves/2021/CVE-2021-43798.yaml",
                # Admin panel information disclosure - not a high-severity one.
                "http/cves/2021/CVE-2021-24917.yaml",
                # caused multiple FPs: travis configuration file provided by a framework without much interesting information.
                "http/exposures/files/travis-ci-disclosure.yaml",
                # At CERT.PL we don't report exposed CMS panels, as having them exposed is a standard workflow for small institutions.
                # Feel free to make a different decision.
                "http/exposed-panels/alfresco-detect.yaml",
                "http/exposed-panels/concrete5/concrete5-panel.yaml",
                "http/exposed-panels/contao-login-panel.yaml",
                "http/exposed-panels/craftcms-admin-panel.yaml",
                "http/exposed-panels/django-admin-panel.yaml",
                "http/exposed-panels/drupal-login.yaml",
                "http/exposed-panels/ez-publish-panel.yaml",
                "http/exposed-panels/joomla-panel.yaml",
                "http/exposed-panels/kentico-login.yaml",
                "http/exposed-panels/liferay-portal.yaml",
                "http/exposed-panels/strapi-panel.yaml",
                "http/exposed-panels/typo3-login.yaml",
                "http/exposed-panels/umbraco-login.yaml",
                "http/exposed-panels/wordpress-login.yaml",
                # At CERT PL we don't report exposed webmails, as it's a standard practice to expose them - feel free to
                # make different decision.
                "http/exposed-panels/squirrelmail-login.yaml",
                "http/exposed-panels/horde-webmail-login.yaml",
                "http/exposed-panels/horde-login-panel.yaml",
                "http/exposed-panels/zimbra-web-login.yaml",
                # These are Tomcat docs, not application docs
                "http/exposed-panels/tomcat/tomcat-exposed-docs.yaml",
                # Generic API docs
                "http/exposed-panels/arcgis/arcgis-rest-api.yaml",
                # VPN web portals and other ones that need to be exposed
                "http/exposed-panels/fortinet/fortinet-fortigate-panel.yaml",
                "http/exposed-panels/checkpoint/ssl-network-extender.yaml",
                "http/exposed-panels/pulse-secure-panel.yaml",
                "http/exposed-panels/pulse-secure-version.yaml",
                "http/exposed-panels/cas-login.yaml",
                # Too small impact to report
                "http/exposed-panels/webeditors-check-detect.yaml",
                # CRMs and ticketing systems - it's a standard practice to have them exposed in a small organization
                "http/exposed-panels/jira-detect.yaml",
                "http/exposed-panels/mantisbt-panel.yaml",
                "http/exposed-panels/mautic-crm-panel.yaml",
                "http/exposed-panels/osticket-panel.yaml:",
                # Mostly meant to be publicly accessible
                "http/exposed-panels/bigbluebutton-login.yaml",
                "http/exposed-panels/ilias-panel.yaml",
            ]
        ),
        cast=decouple.Csv(str),
    )

    # A comma-separated list of Nuclei templates to be used besides the standard list.
    # vulnerabilities/generic/crlf-injection.yaml was present here but is not anymore due to
    # a significant number of false positives
    NUCLEI_ADDITIONAL_TEMPLATES = decouple.config("NUCLEI_ADDITIONAL_TEMPLATES", default=",".join([
            "vulnerabilities/generic/basic-xss-prober.yaml",
            "exposures/configs/ftp-credentials-exposure.yaml",
            "http/misconfiguration/shell-history.yaml",
            "http/misconfiguration/springboot/springboot-env.yaml",
            "http/misconfiguration/springboot/springboot-threaddump.yaml",
            "http/misconfiguration/springboot/springboot-httptrace.yaml",
            "http/misconfiguration/springboot/springboot-logfile.yaml",
            "http/misconfiguration/springboot/springboot-dump.yaml",
            "http/misconfiguration/springboot/springboot-trace.yaml",
            "http/misconfiguration/springboot/springboot-auditevents.yaml",
            "http/exposures/logs/roundcube-log-disclosure.yaml",
            "http/exposures/files/ds-store-file.yaml",
            "misconfiguration/elasticsearch.yaml",
        ]), cast=decouple.Csv(str))

    # == port_scanner settings (artemis/modules/port_scanner.py)
    # custom port list to scan in CSV form (replaces default list)
    CUSTOM_PORT_SCANNER_PORTS = decouple.config("CUSTOM_PORT_SCANNER_PORTS", default="", cast=decouple.Csv(int))

    # the number of open ports we consider to be too much and a false positive - if we observe more
    # open ports, we trim by performing an intersection of the result with the list of 100 most popular ones.
    PORT_SCANNER_MAX_NUM_PORTS = decouple.config("PORT_SCANNER_MAX_NUM_PORTS", default=100, cast=int)

    # == postman settings (artemis/modules/postman.py)
    # E-mail addresses (from and to) that will be used to test whether a server is an open relay or allows
    # sending e-mails to any address.
    POSTMAN_MAIL_FROM = decouple.config("POSTMAN_MAIL_FROM", default="from@example.com")
    POSTMAN_MAIL_TO = decouple.config("POSTMAN_MAIL_TO", default="to@example.com")

    # == shodan settings (artemis/modules/shodan_vulns.py)
    # Shodan API key so that Shodan vulnerabilities will be displayed in Artemis
    SHODAN_API_KEY = decouple.config("SHODAN_API_KEY", default="")

    # == vcs reporter settings (artemis/reporting/modules/vcs/reporter.py)
    # Maximum size of the VCS (e.g. SVN) db file
    VCS_MAX_DB_SIZE_BYTES = decouple.config("VCS_MAX_DB_SIZE_BYTES", default=1024 * 1024 * 5)

    # == wp_scanner settings (artemis/modules/wp_scanner.py)
    # After what number of days we consider the WordPress version to be obsolete
    # This is a long threshold because WordPress maintains a separate list of insecure versions, so "old" doesn't
    # mean "insecure" here.
    WORDPRESS_VERSION_AGE_DAYS = decouple.config("WORDPRESS_VERSION_AGE_DAYS", default=90, cast=int)

    # == wordpress_bruter settings (artemis/modules/wordpress_bruter.py)
    # Wordpress_bruter extracts the site name to brute-force passwords. For example, if it observes
    # projectname.example.com it will bruteforce projectname123, projectname2023, ...
    # This list describes what domain prefixes to strip (e.g. www) so that we bruteforce projectname123, not
    # www123, when testing www.projectname.example.com.
    WORDPRESS_BRUTER_STRIPPED_PREFIXES = decouple.config(
        "WORDPRESS_BRUTER_STRIPPED_PREFIXES", default="www", cast=decouple.Csv(str)
    )
