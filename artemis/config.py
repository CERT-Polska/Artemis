from os import getenv


class Config:
    NOT_INTERESTING_PATHS = getenv("NOT_INTERESTING_PATHS", "/icon/,/icons/").split(",")
    DB_CONN_STR = getenv("DB_CONN_STR", "")
    BROKER = getenv("BROKER", "")
    NMAP_CACHE_DURATION = int(getenv("NMAP_CACHE_DURATION", "3600"))
    SHODAN_API_KEY = getenv("SHODAN_API_KEY", "")

    POSTMAN_MAIL_FROM = getenv("POSTMAN_MAIL_FROM", "")
    POSTMAN_MAIL_TO = getenv("POSTMAN_MAIL_TO", "")

    MAX_HTTP_REQUEST_TASKS_PER_IP = int(getenv("MAX_HTTP_REQUEST_TASKS_PER_IP", 3))
    MAX_HTTP_REQUEST_TASKS_TOTAL = int(getenv("MAX_HTTP_REQUEST_TASKS_TOTAL", 50))
