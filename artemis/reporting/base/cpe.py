from typing import Any, Optional

# A CPE name may come in one of two bindings: the current 2.3 formatted string
# (cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*) or the older 2.2 URI (cpe:/a:redhat:infinispan).
# Both are accepted
CPE_PREFIXES = ("cpe:2.3:", "cpe:/")


def parse_cpe(value: Any) -> Optional[str]:
    """Returns the value if it looks like a CPE name (https://en.wikipedia.org/wiki/Common_Platform_Enumeration).

    Only the binding prefix is checked, not the structure - the point is to drop values that clearly
    aren't CPE names, since they come from sources we don't control and would otherwise be exported as if they were.
    Anything (not only a string) may be passed here.
    """
    if not isinstance(value, str):
        return None

    cpe: str = value.strip()

    # A bare prefix with nothing after it names no product, so it's of no use to anybody reading the asset.
    if not any(cpe.startswith(prefix) and len(cpe) > len(prefix) for prefix in CPE_PREFIXES):
        return None

    return cpe
