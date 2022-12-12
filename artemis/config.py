import decouple


class Config:
    NOT_INTERESTING_PATHS = decouple.config("NOT_INTERESTING_PATHS", default="/icon/,/icons/", cast=decouple.Csv(str))
    DB_CONN_STR = decouple.config("DB_CONN_STR", default="")
    BROKER = decouple.config("BROKER", default="")
    SHODAN_API_KEY = decouple.config("SHODAN_API_KEY", default="")

    POSTMAN_MAIL_FROM = decouple.config("POSTMAN_MAIL_FROM", default="")
    POSTMAN_MAIL_TO = decouple.config("POSTMAN_MAIL_TO", default="")

    ALLOW_SCANNING_PUBLIC_SUFFIXES = decouple.config("ALLOW_SCANNING_PUBLIC_SUFFIXES", default=False, cast=bool)

    # This determines the parallelism for asyncio parallel scanning. For each async scanning
    # (e.g. the one spawned by bruter) the maximum number of coroutines running concurrently
    # will be MAX_ASYNC_PER_LOOP.
    MAX_ASYNC_PER_LOOP = decouple.config("MAX_ASYNC_PER_LOOP", cast=int, default=10)
