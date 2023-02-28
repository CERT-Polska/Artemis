from publicsuffixlist import PublicSuffixList

PUBLIC_SUFFIX_LIST = PublicSuffixList()


def is_main_domain(domain: str) -> bool:
    """
    Main domain (e.g. of an institution) is one that is registered directly under a public suffix.
    """
    domain_items = [item for item in domain.split(".") if item]
    if len(domain_items) <= 1:
        return False

    return bool(PUBLIC_SUFFIX_LIST.publicsuffix(".".join(domain_items[1:])))


def is_subdomain(subdomain_candidate: str, parent_domain_candidate: str) -> bool:
    # Split both domains by dots, so that www.google.com becomes ['www', 'google', 'com']
    subdomain_candidate_items = [item for item in subdomain_candidate.split(".") if item]
    parent_domain_candidate_items = [item for item in parent_domain_candidate.split(".") if item]

    # Make sure that subdomain_candidate_items ends with parent_domain_candidate_items
    # (e.g. ['www', 'google', 'pl'] ends with ['google', 'pl']
    return subdomain_candidate_items[-len(parent_domain_candidate_items) :] == parent_domain_candidate_items
