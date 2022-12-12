import decouple


class Config:
    NOT_INTERESTING_PATHS = decouple.config("NOT_INTERESTING_PATHS", default="/icon/,/icons/", cast=decouple.Csv(str))
    DB_CONN_STR = decouple.config("DB_CONN_STR", default="")
    BROKER = decouple.config("BROKER", default="")
    SHODAN_API_KEY = decouple.config("SHODAN_API_KEY", default="")

    POSTMAN_MAIL_FROM = decouple.config("POSTMAN_MAIL_FROM", default="")
    POSTMAN_MAIL_TO = decouple.config("POSTMAN_MAIL_TO", default="")

    ALLOW_SCANNING_PUBLIC_SUFFIXES = decouple.config("ALLOW_SCANNING_PUBLIC_SUFFIXES", default=False, cast=bool)

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

    # This determines the parallelism for asyncio parallel scanning. For each async scanning
    # (e.g. the one spawned by bruter) the maximum number of coroutines running concurrently
    # will be MAX_ASYNC_PER_LOOP.
    MAX_ASYNC_PER_LOOP = decouple.config("MAX_ASYNC_PER_LOOP", cast=int, default=10)
