from publicsuffixlist import PublicSuffixList

PUBLIC_SUFFIX_LIST = PublicSuffixList()


def is_main_domain(domain: str) -> bool:
    """
    Main domain (e.g. of an institution) is one that is registered directly under a public suffix.
    """
    return PUBLIC_SUFFIX_LIST.privatesuffix(domain) == domain  # type: ignore


def is_subdomain(candidate: str, parent_domain: str, allow_equal: bool = True) -> bool:
    # Split both domains by dots, so that www.google.com becomes ['www', 'google', 'com']
    candidate_items = [item for item in candidate.split(".") if item]
    parent_domain_items = [item for item in parent_domain.split(".") if item]

    # Make sure that candidate_items ends with parent_domain_items
    # (e.g. ['www', 'google', 'pl'] ends with ['google', 'pl']).
    #
    # If allow_equal is set to True, we allow the case that candidate is equal to
    # parent_domain - if it's not, we expect candidate to be an actual subdomain
    # of parent_domain.
    return candidate_items[-len(parent_domain_items) :] == parent_domain_items and (
        allow_equal or len(candidate_items) != len(parent_domain_items)
    )
