from os import getenv


class Config:
    NOT_INTERESTING_PATHS = getenv("NOT_INTERESTING_PATHS", "/icon/,/icons/").split(",")
    DB_CONN_STR = getenv("DB_CONN_STR", "")
    BROKER = getenv("BROKER", "")
    NMAP_CACHE_DURATION = int(getenv("NMAP_CACHE_DURATION", "3600"))
    SHODAN_API_KEY = getenv("SHODAN_API_KEY", "")

    POSTMAN_MAIL_FROM = getenv("POSTMAN_MAIL_FROM", "")
    POSTMAN_MAIL_TO = getenv("POSTMAN_MAIL_TO", "")

    # This determines the http parallelism for asyncio parallel scanning. For each container that runs
    # the scanning, the number of parallel requests would be:
    # min(
    #   CONTAINER_MAX_PARALLEL_HTTP_REQUESTS,
    #   number of IPs * CONTAINER_PARALLEL_HTTP_REQUESTS_PER_IP
    # )
    # This makes sure we use significant parallelism, but only when the number of IPs we scan is
    # large - if it's not, we don't want to overwhelm any single server.
    CONTAINER_PARALLEL_HTTP_REQUESTS_PER_IP = int(getenv("CONTAINER_PARALLEL_HTTP_REQUESTS_PER_IP", 5))
    CONTAINER_MAX_PARALLEL_HTTP_REQUESTS = int(getenv("CONTAINER_MAX_PARALLEL_HTTP_REQUESTS", 100))
