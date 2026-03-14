from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union
from urllib.parse import urlparse

HeaderValue = Union[str, Sequence[str]]


@dataclass(frozen=True)
class CookieIssue:
    code: str
    severity: str
    title: str
    details: Dict[str, Any]


@dataclass(frozen=True)
class ParsedCookie:
    name: str
    value: str
    attrs: Dict[str, Optional[str]]


def _get_header_values(headers: Mapping[str, HeaderValue], name: str) -> List[str]:
    found: List[str] = []
    for k, v in headers.items():
        if str(k).lower() == name.lower():
            if isinstance(v, (list, tuple)):
                found.extend([str(x) for x in v])
            else:
                found.append(str(v))
    return found


def parse_set_cookie_header(set_cookie_value: str) -> Optional[ParsedCookie]:
    if not set_cookie_value or "=" not in set_cookie_value:
        return None

    segments = [s.strip() for s in set_cookie_value.split(";")]
    if not segments:
        return None

    name_value = segments[0]

    if "=" not in name_value:
        return None

    name, value = name_value.split("=", 1)

    attrs: Dict[str, Optional[str]] = {}

    for seg in segments[1:]:
        if "=" in seg:
            k, v = seg.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[seg.strip().lower()] = None

    return ParsedCookie(name=name.strip(), value=value.strip(), attrs=attrs)


def analyze_cookie_headers(
    response_headers: Mapping[str, HeaderValue],
    *,
    request_url: Optional[str] = None,
) -> List[CookieIssue]:

    set_cookie_values = _get_header_values(response_headers, "Set-Cookie")

    cookies: List[ParsedCookie] = []

    for v in set_cookie_values:
        parsed = parse_set_cookie_header(v)
        if parsed:
            cookies.append(parsed)

    issues: List[CookieIssue] = []

    scheme = None
    host = None

    if request_url:
        parsed_url = urlparse(request_url)
        scheme = parsed_url.scheme.lower()
        host = parsed_url.hostname

    for cookie in cookies:

        attrs = cookie.attrs

        secure = "secure" in attrs
        httponly = "httponly" in attrs
        samesite = attrs.get("samesite")

        samesite_l = samesite.lower() if isinstance(samesite, str) else None

        if samesite_l == "none" and not secure:
            issues.append(
                CookieIssue(
                    code="COOKIE_SAMESITE_NONE_WITHOUT_SECURE",
                    severity="high",
                    title="Cookie SameSite=None without Secure",
                    details={"cookie": cookie.name},
                )
            )

        if scheme == "https" and not secure:
            issues.append(
                CookieIssue(
                    code="COOKIE_MISSING_SECURE",
                    severity="medium",
                    title="Cookie missing Secure attribute",
                    details={"cookie": cookie.name},
                )
            )

        if not httponly:
            issues.append(
                CookieIssue(
                    code="COOKIE_MISSING_HTTPONLY",
                    severity="medium",
                    title="Cookie missing HttpOnly attribute",
                    details={"cookie": cookie.name},
                )
            )

        if samesite is None:
            issues.append(
                CookieIssue(
                    code="COOKIE_MISSING_SAMESITE",
                    severity="low",
                    title="Cookie missing SameSite attribute",
                    details={"cookie": cookie.name},
                )
            )

        if "domain" in attrs:
            issues.append(
                CookieIssue(
                    code="COOKIE_DOMAIN_ATTRIBUTE_SET",
                    severity="low",
                    title="Cookie sets Domain attribute",
                    details={"cookie": cookie.name, "domain": attrs.get("domain")},
                )
            )

    return issues


def run_for_url(
    url: str,
    *,
    http_client: Any,
    timeout_s: int = 15,
) -> List[CookieIssue]:

    response = http_client.request("GET", url, headers={}, timeout=timeout_s)

    headers = getattr(response, "headers", {}) or {}

    return analyze_cookie_headers(headers, request_url=url)