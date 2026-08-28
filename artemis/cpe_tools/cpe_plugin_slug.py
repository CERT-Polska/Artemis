import re
from collections.abc import Callable


def _wordpress_plugin_slug(url: str) -> tuple[str, str] | None:
    match = re.match(r"https?://(?:www\.)?wordpress\.org/plugins/([^/#?]+)", url, re.IGNORECASE)
    return ("wordpress", match.group(1).lower()) if match else None


def _joomla_extension_slug(url: str) -> tuple[str, str] | None:
    # The slug is the last (non-numeric) path segment under /extension/. The older
    # /extensions/... tree paths end in numeric IDs and are skipped.
    # example: https://extensions.joomla.org/extension/akeeba-backup/
    match = re.match(r"https?://(?:www\.)?extensions\.joomla\.org/extension/([^#?]*)", url, re.IGNORECASE)
    if not match:
        return None
    slug = match.group(1).rstrip("/").lower().split("/")[-1]
    if not slug or slug.isdigit():
        return None
    return ("joomla", slug)


_CMS_SLUG_EXTRACTORS: list[Callable[[str], tuple[str, str] | None]] = [
    _wordpress_plugin_slug,
    _joomla_extension_slug,
]


def plugin_slug(url: str) -> tuple[str, str] | None:
    for extractor in _CMS_SLUG_EXTRACTORS:
        result = extractor(url)
        if result is not None:
            return result
    return None
