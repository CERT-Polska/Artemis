from os import getenv

import decouple
from redis import Redis
from redis.asyncio import Redis as AsyncRedis


class Config:
    NOT_INTERESTING_PATHS = getenv("NOT_INTERESTING_PATHS", "/icon/,/icons/").split(",")
    DB_CONN_STR = decouple.config("DB_CONN_STR", "")
    BROKER = getenv("BROKER", "")
    NMAP_CACHE_DURATION = int(getenv("NMAP_CACHE_DURATION", "3600"))
    SHODAN_API_KEY = getenv("SHODAN_API_KEY", "")
    SCANNING_USER_AGENT_OVERRIDE = decouple.config("SCANNING_USER_AGENT_OVERRIDE", default="")

    POSTMAN_MAIL_FROM = getenv("POSTMAN_MAIL_FROM", "")
    POSTMAN_MAIL_TO = getenv("POSTMAN_MAIL_TO", "")

    REDIS = Redis.from_url(decouple.config("REDIS_CONN_STR"))
    ASYNC_REDIS = AsyncRedis.from_url(decouple.config("REDIS_CONN_STR"))
    REDIS_CONN_STR = decouple.config("REDIS_CONN_STR")

    HTTP_TIMEOUT_SECONDS = decouple.config("HTTP_TIMEOUT_SECONDS", default=5, cast=int)
    SECONDS_PER_HTTP_REQUEST_FOR_ONE_IP = decouple.config("SECONDS_PER_HTTP_REQUEST_FOR_ONE_IP", default=5, cast=int)
    SCANNING_PACKETS_PER_SECOND_PER_IP = decouple.config("SCANNING_PACKETS_PER_SECOND_PER_IP", default=1, cast=int)
