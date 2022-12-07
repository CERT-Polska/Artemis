from os import getenv

import decouple


class Config:
    NOT_INTERESTING_PATHS = getenv("NOT_INTERESTING_PATHS", "/icon/,/icons/").split(",")
    DB_CONN_STR = getenv("DB_CONN_STR", "")
    BROKER = getenv("BROKER", "")
    NMAP_CACHE_DURATION = int(getenv("NMAP_CACHE_DURATION", "3600"))
    SHODAN_API_KEY = getenv("SHODAN_API_KEY", "")
    SCANNING_USER_AGENT_OVERRIDE = decouple.config("SCANNING_USER_AGENT_OVERRIDE", default="")

    POSTMAN_MAIL_FROM = getenv("POSTMAN_MAIL_FROM", "")
    POSTMAN_MAIL_TO = getenv("POSTMAN_MAIL_TO", "")
