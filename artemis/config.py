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
    # the scanning, the number of parallel requests would be CONTAINER_MAX_PARALLEL_HTTP_REQUESTS
    CONTAINER_MAX_PARALLEL_HTTP_REQUESTS = int(getenv("CONTAINER_MAX_PARALLEL_HTTP_REQUESTS", 10))
