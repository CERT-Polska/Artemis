import logging
from pathlib import Path

from artemis.cpe_tools.cpe_main_process import (
    LOOKUP_CACHE,
    ensure_index,
    family,
    get_nvd_dir,
    normalize,
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

_MISSING = object()

# The lookup cache can grow unbounded (one entry per distinct product name)
MAX_LOOKUP_CACHE_SIZE = 100_000


def _cache_put(key: tuple[Path, str], value: str | None) -> None:
    while len(LOOKUP_CACHE) >= MAX_LOOKUP_CACHE_SIZE:
        LOOKUP_CACHE.pop(next(iter(LOOKUP_CACHE)), None)
    LOOKUP_CACHE[key] = value


def with_version(cpe: str, version: str) -> str:
    # A CPE 2.3 well-formed name escapes ":" inside fields as %3a, so splitting on
    # ":" always yields exactly 13 components: cpe, 2.3, part, vendor, product,
    # version, update, edition, language, sw_edition, target_sw, target_hw, other.
    VERSION_FIELD_INDEX = 5

    parts = cpe.split(":")
    if len(parts) <= VERSION_FIELD_INDEX:
        return cpe
    parts[VERSION_FIELD_INDEX] = version
    return ":".join(parts)


def resolve(nvd_dir: Path, normalized: str) -> str | None:
    def _tokens(normalized: str) -> list[str]:
        return [t for t in normalized.split() if len(t) > 1 and t not in _STOPWORDS]

    cache_key = (nvd_dir, normalized)
    cached: object = LOOKUP_CACHE.get(cache_key, _MISSING)
    if cached is not _MISSING:
        return cached if isinstance(cached, str) else None

    index = ensure_index(nvd_dir)

    cpe = index.get(normalized)
    if cpe is not None:
        result: str | None = with_version(cpe, "*")
        _cache_put(cache_key, result)
        return result

    tokens = _tokens(normalized)
    if not tokens:
        _cache_put(cache_key, None)
        return None

    token_set = frozenset(tokens)
    candidates: dict[str, str] = {}
    for title, cpe in index.items():
        if token_set.issubset(title.split()):
            candidates.setdefault(family(cpe), cpe)

    result = with_version(next(iter(candidates.values())), "*") if len(candidates) == 1 else None
    _cache_put(cache_key, result)
    return result


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
