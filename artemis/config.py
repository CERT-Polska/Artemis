import decouple
from redis import Redis
from redis.asyncio import Redis as AsyncRedis


class Config:
    NOT_INTERESTING_PATHS = decouple.config("NOT_INTERESTING_PATHS", default="/icon/,/icons/", cast=decouple.Csv(str))
    DB_CONN_STR = decouple.config("DB_CONN_STR", default="")
    BROKER = decouple.config("BROKER", default="")
    SHODAN_API_KEY = decouple.config("SHODAN_API_KEY", default="")
    CUSTOM_USER_AGENT = decouple.config("CUSTOM_USER_AGENT", default="")

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

    # These are not three separate Redis instances. What follows is a connection string (describing
    # how to connect to Redis) and two already constructed Redis clients - sync and async, **both
    # connecting to the same Redis instance**.
    REDIS_CONN_STR = decouple.config("REDIS_CONN_STR")
    REDIS = Redis.from_url(decouple.config("REDIS_CONN_STR"))
    ASYNC_REDIS = AsyncRedis.from_url(decouple.config("REDIS_CONN_STR"))

    HTTP_TIMEOUT_SECONDS = decouple.config("HTTP_TIMEOUT_SECONDS", default=2, cast=int)

    # These two limits are independent - whether the port scanning limits are used doesn't affect
    # the requests limit and vice versa.
    SECONDS_PER_REQUEST_FOR_ONE_IP = decouple.config("SECONDS_PER_REQUEST_FOR_ONE_IP", default=2, cast=int)
    SCANNING_PACKETS_PER_SECOND_PER_IP = decouple.config("SCANNING_PACKETS_PER_SECOND_PER_IP", default=2, cast=int)

    # When a resource is locked using artemis.resource_lock.ResourceLock or
    # artemis.resource_lock.AsyncResourceLock, a retry will be performed in the
    # next LOCK_SLEEP_MIN_SECONDS..LOCK_SLEEP_MAX_SECONDS seconds.
    LOCK_SLEEP_MIN_SECONDS = decouple.config("LOCK_SLEEP_MIN_SECONDS", default=0.1, cast=float)
    LOCK_SLEEP_MAX_SECONDS = decouple.config("LOCK_SLEEP_MAX_SECONDS", default=1, cast=float)

    # Locks are not permanent, because a service that has acquired a lock may get restarted or killed.
    # This is the lock default expiry time.
    DEFAULT_LOCK_EXPIRY_SECONDS = decouple.config("DEFAULT_LOCK_EXPIRY_SECONDS", default=3600, cast=int)

    # A threshold in case the server reports too much files with 200 status code,
    # and we want to skip this as a false positive. 0.1 means 10%.
    BRUTER_FALSE_POSITIVE_THRESHOLD = 0.1

    # We save response content in some cases - in order not to overload the DB, this determines how long
    # the saved content would be.
    CONTENT_PREFIX_SIZE = 2048

    # If set to True, bruter will follow redirects. If to False, a redirect will be interpreted that a URL
    # doesn't exist, thus decreasing the number of false positives at the cost of losing some true positives.
    BRUTER_FOLLOW_REDIRECTS = decouple.config("BRUTER_FOLLOW_REDIRECTS", default=True, cast=bool)
