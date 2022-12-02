from os import getenv


class Config:
    DB_CONN_STR = getenv("DB_CONN_STR", "")
    BROKER = getenv("BROKER", "")
    NMAP_CACHE_DURATION = int(getenv("NMAP_CACHE_DURATION", "3600"))
    SHODAN_API_KEY = getenv("SHODAN_API_KEY", "")

    POSTMAN_MAIL_FROM = getenv("POSTMAN_MAIL_FROM", "")
    POSTMAN_MAIL_TO = getenv("POSTMAN_MAIL_TO", "")

    # A threshold in case the server reports too much files with 200 status code,
    # and we want to skip this as a false positive. 0.1 means 10%.
    BRUTER_FOUND_FILES_PERCENTAGE_THRESHOLD_TO_SKIP_REPORTING = 0.1
