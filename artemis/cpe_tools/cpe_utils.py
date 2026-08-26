import logging
from pathlib import Path

from artemis.cpe_tools.cpe_main_process import (
    ensure_plugin_index,
    ensure_title_index,
    ensure_url_index,
    family,
    get_nvd_dir,
    normalize,
    normalize_url,
    split_cpe,
)

logger = logging.getLogger(__name__)


# Words that carry no discriminative value for product matching.
_STOPWORDS = frozenset(
    {
        "the",
        "and",
        "of",
        "for",
        "a",
        "an",
        "inc",
        "llc",
        "ltd",
        "corp",
        "co",
        "gmbh",
        "plc",
        "sa",
    }
)


def with_version(cpe: str, version: str) -> str:
    # Components are: cpe, 2.3, part, vendor, product, version, update, edition,
    # language, sw_edition, target_sw, target_hw, other. Replace the version field
    # (index 5) and re-join;
    VERSION_FIELD_INDEX = 5

    parts = split_cpe(cpe)
    if len(parts) <= VERSION_FIELD_INDEX:
        return cpe
    parts[VERSION_FIELD_INDEX] = version
    return ":".join(parts)


def resolve(nvd_dir: Path, normalized: str) -> str | None:
    def _tokens(normalized: str) -> list[str]:
        return [t for t in normalized.split() if len(t) > 1 and t not in _STOPWORDS]

    index = ensure_title_index(nvd_dir)

    cpe = index.get(normalized)
    if cpe is not None:
        return with_version(cpe, "*")

    tokens = _tokens(normalized)
    if not tokens:
        return None

    token_set = frozenset(tokens)
    candidates: dict[str, str] = {}
    for title, cpe in index.items():
        if token_set.issubset(title.split()):
            candidates.setdefault(family(cpe), cpe)

    return with_version(next(iter(candidates.values())), "*") if len(candidates) == 1 else None


def lookup_cpe(name: str, version: str | None = None) -> str | None:
    """Resolve a free-form product name to an authoritative NVD CPE 2.3 name.

    Returns ``None`` when there is no match, the dictionary is unavailable, or
    the match is ambiguous across more than one vendor:product family.
    """
    if not isinstance(name, str) or not name.strip():
        return None
    nvd_dir = get_nvd_dir()
    normalized = normalize(name)
    if not normalized:
        return None
    family_cpe = resolve(nvd_dir, normalized)
    if family_cpe is None:
        return None
    return with_version(family_cpe, version) if version else family_cpe


def lookup_cpe_by_plugin_slug(slug: str, cms: str = "wordpress", version: str | None = None) -> str | None:
    """Resolve a CMS plugin slug to an authoritative NVD CPE 2.3 name.

    The plugin index stores slugs namespaced by CMS (e.g. ``wordpress:<slug>``)

    Returns ``None`` when the dictionary is unavailable or no plugin CPE
    references that slug.
    """
    if not isinstance(slug, str) or not slug.strip():
        return None
    plugins = ensure_plugin_index(get_nvd_dir())
    cpe = plugins.get(f"{cms}:{slug.strip().lower()}")
    if cpe is None:
        return None
    return with_version(cpe, version) if version else with_version(cpe, "*")


def lookup_cpe_by_url(url: str, version: str | None = None) -> str | None:
    """Resolve a reference URL to an authoritative NVD CPE 2.3 name.

    The url index stores every ref URL seen on a CPE, keyed by
    its normalized form. First-seen wins when the same normalized URL appears on more
    than one CPE.

    Returns ``None`` when the dictionary is unavailable or no CPE
    references that URL.
    """
    if not isinstance(url, str) or not url.strip():
        return None
    key = normalize_url(url)
    if not key:
        return None
    urls = ensure_url_index(get_nvd_dir())
    cpe = urls.get(key)
    if cpe is None:
        return None
    return with_version(cpe, version) if version else with_version(cpe, "*")
