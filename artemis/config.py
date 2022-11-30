from os import getenv


class Config:
    FOLDERS_THAT_DONT_HAVE_INTERESTING_CONTENT = getenv(
        "FOLDERS_THAT_DONT_HAVE_INTERESTING_CONTENT", "/icon/,/icons/"
    ).split(",")
    DB_CONN_STR = getenv("DB_CONN_STR", "")
    BROKER = getenv("BROKER", "")
    NMAP_CACHE_DURATION = int(getenv("NMAP_CACHE_DURATION", "3600"))
    SHODAN_API_KEY = getenv("SHODAN_API_KEY", "")

    POSTMAN_MAIL_FROM = getenv("POSTMAN_MAIL_FROM", "")
    POSTMAN_MAIL_TO = getenv("POSTMAN_MAIL_TO", "")
