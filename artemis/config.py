import decouple
from redis import Redis
from redis.asyncio import Redis as AsyncRedis


class Config:
    NOT_INTERESTING_PATHS = decouple.config("NOT_INTERESTING_PATHS", default="/icon/,/icons/", cast=decouple.Csv(str))
    DB_CONN_STR = decouple.config("DB_CONN_STR", default="")
    BROKER = decouple.config("BROKER", default="")
    SHODAN_API_KEY = decouple.config("SHODAN_API_KEY", default="")
    SCANNING_USER_AGENT_OVERRIDE = decouple.config("SCANNING_USER_AGENT_OVERRIDE", default="")

    POSTMAN_MAIL_FROM = decouple.config("POSTMAN_MAIL_FROM", default="")
    POSTMAN_MAIL_TO = decouple.config("POSTMAN_MAIL_TO", default="")

    ALLOW_SCANNING_PUBLIC_SUFFIXES = decouple.config("ALLOW_SCANNING_PUBLIC_SUFFIXES", default=False, cast=bool)

    # This determines the parallelism for asyncio parallel scanning. For each async scanning
    # (e.g. the one spawned by bruter) the maximum number of coroutines running concurrently
    # will be MAX_ASYNC_PER_LOOP.
    MAX_ASYNC_PER_LOOP = decouple.config("MAX_ASYNC_PER_LOOP", cast=int, default=10)

    # These are not three separate Redis instances. What follows is a connection string (describing
    # how to connect to Redis) and two already constructed Redis clients - sync and async, **both
    # connecting to the same Redis instance**.
    REDIS_CONN_STR = decouple.config("REDIS_CONN_STR")
    REDIS = Redis.from_url(decouple.config("REDIS_CONN_STR"))
    ASYNC_REDIS = AsyncRedis.from_url(decouple.config("REDIS_CONN_STR"))

    HTTP_TIMEOUT_SECONDS = decouple.config("HTTP_TIMEOUT_SECONDS", default=5, cast=int)
    SECONDS_PER_REQUEST_FOR_ONE_IP = decouple.config("SECONDS_PER_REQUEST_FOR_ONE_IP", default=5, cast=int)
    SCANNING_PACKETS_PER_SECOND_PER_IP = decouple.config("SCANNING_PACKETS_PER_SECOND_PER_IP", default=1, cast=int)

    # When a resource is locked using artemis.resource_lock.ResourceLock or
    # artemis.resource_lock.AsyncResourceLock, a retry will be performed in the
    # next LOCK_SLEEP_MIN_SECONDS..LOCK_SLEEP_MAX_SECONDS seconds.
    LOCK_SLEEP_MIN_SECONDS = decouple.config("LOCK_SLEEP_MIN_SECONDS", default=1, cast=int)
    LOCK_SLEEP_MAX_SECONDS = decouple.config("LOCK_SLEEP_MAX_SECONDS", default=5, cast=int)
