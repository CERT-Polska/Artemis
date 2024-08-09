from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from typing import Any, Callable, Dict

from requests import Response
from requests_cache import CachedSession
from requests_cache.backends.filesystem import FileCache

from artemis import utils
from artemis.config import Config


class InvalidResponseException(Exception):
    pass


@dataclass
class CachedURL:
    url: str
    validator: Callable[[Dict[Any, Any]], bool]

    def get(self) -> Response:
        return FallbackAPICache.get(self.url)


class FallbackAPICache:
    LOGGER = utils.build_logger(__name__)

    CACHE = CachedSession(
        backend=FileCache("/cache"),
        cache_control=False,
        expire_after=timedelta(seconds=3600),
        allowable_codes=[200],
        stale_if_error=True,
    )

    class Urls(Enum):
        JOOMLA_LATEST_RELEASE = CachedURL(
            "https://api.github.com/repos/joomla/joomla-cms/releases/latest",
            lambda item: "url" in item and "author" in item,
        )
        WORDPRESS_TAGS = CachedURL(
            "https://api.github.com/repos/WordPress/WordPress/git/refs/tags",
            lambda item: len(item) > 10 and "ref" in item[0] and "url" in item[0],
        )
        WORDPRESS_STABLE_CHECK = CachedURL(
            "https://api.wordpress.org/core/stable-check/1.0/", lambda item: item["1.0.2"] == "insecure"
        )
        WORDPRESS_PLUGINS_LIST = CachedURL(
            "https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[page]=1&request[per_page]=1000",
            lambda item: "info" in item
            and "page" in item["info"]
            and "plugins" in item
            and "name" in item["plugins"][0],
        )

    @classmethod
    def get(cls, url: str, allow_unknown: bool = False) -> Response:
        headers = {}
        if Config.Miscellaneous.CUSTOM_USER_AGENT:
            headers["User-Agent"] = Config.Miscellaneous.CUSTOM_USER_AGENT

        found = None
        for item in cls.Urls:
            if item.value.url == url:
                found = item.value
        if not allow_unknown:
            assert found

        response = FallbackAPICache.CACHE.get(url, headers=headers)

        if found:
            if not found.validator(response.json()):
                raise InvalidResponseException()

        return response

    @classmethod
    def warmup(cls) -> None:
        for url in cls.Urls:
            FallbackAPICache.LOGGER.info("Warming up: %s", url.value.url)
            cls.get(url.value.url)


if __name__ == "__main__":
    FallbackAPICache.warmup()
