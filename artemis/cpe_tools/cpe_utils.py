import logging
import re
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


# Components of a cpe:2.3 name are: cpe, 2.3, part, vendor, product, version, update,
# edition, language, sw_edition, target_sw, target_hw, other.
_VERSION_FIELD_INDEX = 5

# A version has to look like one: a digit first, then only characters versions are made of.
# Anchored with ``\Z``, because Python's ``$`` also matches before a trailing newline.
_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.\-+]*\Z")


def with_version(cpe: str, version: str) -> str:
    """Replace the version field of a cpe:2.3 name with ``version``, whatever it holds now.

    Used to normalize a dictionary CPE down to its wildcard family. To insert a
    caller-supplied version use ``fill_version`` instead - it validates the value and
    leaves an already-concrete slot alone.
    """
    parts = split_cpe(cpe)
    if len(parts) <= _VERSION_FIELD_INDEX:
        return cpe
    parts[_VERSION_FIELD_INDEX] = version
    return ":".join(parts)


def fill_version(cpe: str, version: str | None) -> str:
    """Substitute ``version`` into the wildcard version slot of a cpe:2.3 name.

    A name carrying ``*`` in the version slot denotes the product as a whole; filling that
    slot narrows it to a single release.

    The CPE comes back unchanged when the version is missing, doesn't look like a version,
    or the slot already carries something concrete that we would rather not contradict.
    """
    if not version or not _VERSION_RE.match(version):
        return cpe
    parts = split_cpe(cpe)
    if len(parts) <= _VERSION_FIELD_INDEX or parts[_VERSION_FIELD_INDEX] != "*":
        return cpe
    return with_version(cpe, version)


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
    return fill_version(family_cpe, version)


def lookup_cpe_by_plugin_slug(slug: str, cms: str, version: str | None = None) -> str | None:
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
    return fill_version(with_version(cpe, "*"), version)


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
    return fill_version(with_version(cpe, "*"), version)
