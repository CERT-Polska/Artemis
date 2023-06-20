import validators
from publicsuffixlist import PublicSuffixList

PUBLIC_SUFFIX_LIST = PublicSuffixList()


def is_domain(candidate: str) -> bool:
    try:
        return validators.domain(candidate)  # type: ignore
    except validators.ValidationFailure:
        return False


def is_main_domain(domain: str) -> bool:
    """
    Main domain (e.g. of an institution) is one that is registered directly under a public suffix.
    """
    return PUBLIC_SUFFIX_LIST.privatesuffix(domain) == domain  # type: ignore


def is_subdomain(candidate: str, parent_domain: str, allow_equal: bool = True) -> bool:
    candidate = candidate.strip(".")
    parent_domain = parent_domain.strip(".")

    if allow_equal and candidate == parent_domain:
        return True

    if not candidate.endswith(parent_domain):
        return False

    tmp = candidate[: -len(parent_domain)]
    return tmp.endswith(".") and len(tmp) > 1
