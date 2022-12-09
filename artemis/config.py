from os import getenv

import decouple


class Config:
    NOT_INTERESTING_PATHS = getenv("NOT_INTERESTING_PATHS", "/icon/,/icons/").split(",")
    DB_CONN_STR = getenv("DB_CONN_STR", "")
    BROKER = getenv("BROKER", "")
    NMAP_CACHE_DURATION = int(getenv("NMAP_CACHE_DURATION", "3600"))
    SHODAN_API_KEY = getenv("SHODAN_API_KEY", "")

    POSTMAN_MAIL_FROM = getenv("POSTMAN_MAIL_FROM", "")
    POSTMAN_MAIL_TO = getenv("POSTMAN_MAIL_TO", "")

    # By default, Artemis will check whether the reverse DNS lookup for an IP matches
    # the original domain. For example, if we encounter the 1.1.1.1 ip which resolves to
    # new.example.com, Artemis will check whether it is a subdomain of the original task
    # domain.
    #
    # This is to prevent Artemis from randomly walking through the internet after encountering
    # a misconfigured Reverse DNS record (e.g. pointing to a completely different domain).
    #
    # The downside of that is that when you don't provide original domain (e.g. provide
    # an IP to be scanned), the reverse DNS lookup won't happen. Therefore this behavior is
    # configurable and may be turned off.
    CHECK_DOMAIN_IN_REVERSE_IP_LOOKUP = decouple.config("CHECK_DOMAIN_IN_REVERSE_IP_LOOKUP", default=True, cast=bool)
