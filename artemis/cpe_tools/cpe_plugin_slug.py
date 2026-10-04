import re
from collections.abc import Callable


def _wordpress_plugin_slug(url: str) -> tuple[str, str] | None:
    match = re.match(r"https?://(?:www\.)?wordpress\.org/plugins/([^/#?]+)", url, re.IGNORECASE)
    return ("wordpress", match.group(1).lower()) if match else None


_CMS_SLUG_EXTRACTORS: list[Callable[[str], tuple[str, str] | None]] = [_wordpress_plugin_slug]


def plugin_slug(url: str) -> tuple[str, str] | None:
    for extractor in _CMS_SLUG_EXTRACTORS:
        result = extractor(url)
        if result is not None:
            return result
    return None
