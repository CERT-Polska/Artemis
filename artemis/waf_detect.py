import functools
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from artemis import http_requests
from artemis.utils import build_logger

LOGGER = build_logger(__name__)


class WAFType(Enum):
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    AKAMAI = "akamai"
    IMPERVA = "imperva"
    MODSECURITY = "modsecurity"
    SUCURI = "sucuri"
    F5_BIG_IP = "f5_big_ip"
    BARRACUDA = "barracuda"
    FORTIWEB = "fortiweb"
    WORDFENCE = "wordfence"
    CLOUDFRONT = "cloudfront"
    FASTLY = "fastly"
    STACKPATH = "stackpath"
    EDGECAST = "edgecast"
    WALLARM = "wallarm"
    REBLAZE = "reblaze"
    COMODO = "comodo"
    RADWARE = "radware"
    CITRIX_NETSCALER = "citrix_netscaler"
    PALO_ALTO = "palo_alto"
    SOPHOS = "sophos"
    SQUARESPACE = "squarespace"
    SHIELD_SECURITY = "shield_security"
    ITHEMES = "ithemes"
    BULLETPROOF = "bulletproof"
    UNKNOWN = "unknown"


@dataclass
class WAFInfo:
    detected: bool
    waf_type: WAFType
    confidence: str
    evidence: str
    blocks_payloads: bool = False
    additional_detections: List[str] = field(default_factory=list)


HEADER_SIGNATURES: List[Tuple[str, str, WAFType, str]] = [
    ("server", r"cloudflare", WAFType.CLOUDFLARE, "high"),
    ("cf-ray", r".+", WAFType.CLOUDFLARE, "high"),
    ("cf-cache-status", r".+", WAFType.CLOUDFLARE, "medium"),
    ("cf-mitigated", r".+", WAFType.CLOUDFLARE, "high"),
    ("cf-chl-bypass", r".+", WAFType.CLOUDFLARE, "high"),
    ("x-sucuri-id", r".+", WAFType.SUCURI, "high"),
    ("x-sucuri-cache", r".+", WAFType.SUCURI, "high"),
    ("server", r"Sucuri", WAFType.SUCURI, "high"),
    ("server", r"AkamaiGHost", WAFType.AKAMAI, "high"),
    ("x-akamai-transformed", r".+", WAFType.AKAMAI, "high"),
    ("akamai-grn", r".+", WAFType.AKAMAI, "high"),
    ("x-akamai-session-info", r".+", WAFType.AKAMAI, "medium"),
    ("x-akamai-request-id", r".+", WAFType.AKAMAI, "medium"),
    ("x-cdn", r"Imperva", WAFType.IMPERVA, "high"),
    ("x-iinfo", r".+", WAFType.IMPERVA, "medium"),
    ("x-cdn", r"Incapsula", WAFType.IMPERVA, "high"),
    ("set-cookie", r"incap_ses_|visid_incap_", WAFType.IMPERVA, "high"),
    ("set-cookie", r"_Incapsula_Resource", WAFType.IMPERVA, "high"),
    ("x-amzn-waf-action", r".+", WAFType.AWS_WAF, "high"),
    ("x-amzn-requestid", r".+", WAFType.AWS_WAF, "low"),
    ("x-amz-cf-id", r".+", WAFType.CLOUDFRONT, "medium"),
    ("x-amz-cf-pop", r".+", WAFType.CLOUDFRONT, "medium"),
    ("server", r"CloudFront", WAFType.CLOUDFRONT, "high"),
    ("x-cache", r".*cloudfront.*", WAFType.CLOUDFRONT, "medium"),
    ("server", r"mod_security", WAFType.MODSECURITY, "high"),
    ("server", r"NOYB", WAFType.MODSECURITY, "medium"),
    ("x-modsecurity-id", r".+", WAFType.MODSECURITY, "high"),
    ("x-modsecurity-error-type", r".+", WAFType.MODSECURITY, "high"),
    ("server", r"BigIP|BIG-IP", WAFType.F5_BIG_IP, "high"),
    ("x-cnection", r".+", WAFType.F5_BIG_IP, "medium"),
    ("set-cookie", r"TS[a-zA-Z0-9]{3,8}=", WAFType.F5_BIG_IP, "medium"),
    ("set-cookie", r"BIGipServer", WAFType.F5_BIG_IP, "high"),
    ("x-wa-info", r".+", WAFType.F5_BIG_IP, "medium"),
    ("server", r"Barracuda", WAFType.BARRACUDA, "high"),
    ("set-cookie", r"barra_counter_session", WAFType.BARRACUDA, "high"),
    ("set-cookie", r"BNI__BARRACUDA_LB_COOKIE", WAFType.BARRACUDA, "high"),
    ("server", r"FortiWeb", WAFType.FORTIWEB, "high"),
    ("set-cookie", r"fortiwafsid", WAFType.FORTIWEB, "high"),
    ("x-fortigate-id", r".+", WAFType.FORTIWEB, "medium"),
    ("server", r"Fastly", WAFType.FASTLY, "high"),
    ("x-fastly-request-id", r".+", WAFType.FASTLY, "high"),
    ("x-served-by", r"cache-", WAFType.FASTLY, "medium"),
    ("via", r".*varnish.*", WAFType.FASTLY, "low"),
    ("x-sp-waf", r".+", WAFType.STACKPATH, "high"),
    ("server", r"StackPath", WAFType.STACKPATH, "high"),
    ("x-sp-url", r".+", WAFType.STACKPATH, "medium"),
    ("server", r"nginx-wallarm", WAFType.WALLARM, "high"),
    ("x-wallarm-waf-check", r".+", WAFType.WALLARM, "high"),
    ("server", r"Reblaze", WAFType.REBLAZE, "high"),
    ("set-cookie", r"rbzid=", WAFType.REBLAZE, "high"),
    ("server", r"Protected by COMODO", WAFType.COMODO, "high"),
    ("x-sl-compstate", r".+", WAFType.RADWARE, "high"),
    ("set-cookie", r"X-SL-Session", WAFType.RADWARE, "high"),
    ("set-cookie", r"ns_af=", WAFType.CITRIX_NETSCALER, "high"),
    ("set-cookie", r"citrix_ns_id", WAFType.CITRIX_NETSCALER, "high"),
    ("via", r"NS-CACHE", WAFType.CITRIX_NETSCALER, "medium"),
    ("set-cookie", r"NSC_", WAFType.CITRIX_NETSCALER, "medium"),
    ("x-pan-waf", r".+", WAFType.PALO_ALTO, "high"),
    ("server", r"Sophos", WAFType.SOPHOS, "high"),
    ("x-powered-by", r"Shield Security", WAFType.SHIELD_SECURITY, "high"),
    ("set-cookie", r"wp-shield", WAFType.SHIELD_SECURITY, "medium"),
]


BLOCK_PAGE_SIGNATURES: List[Tuple[str, WAFType]] = [
    (r"Attention Required.*Cloudflare", WAFType.CLOUDFLARE),
    (r"cf-error-details", WAFType.CLOUDFLARE),
    (r"Ray ID:", WAFType.CLOUDFLARE),
    (r"Cloudflare Ray ID", WAFType.CLOUDFLARE),
    (r"__cf_chl_tk", WAFType.CLOUDFLARE),
    (r"cf-browser-verification", WAFType.CLOUDFLARE),
    (r"cf_chl_prog", WAFType.CLOUDFLARE),
    (r"challenges\.cloudflare\.com", WAFType.CLOUDFLARE),
    (r"Access Denied.*Sucuri", WAFType.SUCURI),
    (r"sucuri\.net/privacy", WAFType.SUCURI),
    (r"<h2>Access Denied - Sucuri Website Firewall</h2>", WAFType.SUCURI),
    (r"Sucuri WebSite Firewall", WAFType.SUCURI),
    (r"cloudproxy@sucuri\.net", WAFType.SUCURI),
    (r"Reference #\d+\.\w+\.\d+", WAFType.AKAMAI),
    (r"AkamaiGHost", WAFType.AKAMAI),
    (r"Access Denied.*akamai", WAFType.AKAMAI),
    (r"akamaierror", WAFType.AKAMAI),
    (r"Powered by Imperva", WAFType.IMPERVA),
    (r"Incapsula incident ID", WAFType.IMPERVA),
    (r"_Incapsula_Resource", WAFType.IMPERVA),
    (r"Request unsuccessful\. Incapsula", WAFType.IMPERVA),
    (r"Incapsula_Resource", WAFType.IMPERVA),
    (r"by Imperva First", WAFType.IMPERVA),
    (r"This request was blocked by the security rules", WAFType.MODSECURITY),
    (r"ModSecurity", WAFType.MODSECURITY),
    (r"<title>403 Forbidden</title>.*mod_security", WAFType.MODSECURITY),
    (r"NOYB", WAFType.MODSECURITY),
    (r"not acceptable.*mod_security", WAFType.MODSECURITY),
    (r"rules of the mod_security module", WAFType.MODSECURITY),
    (r"The requested URL was rejected", WAFType.F5_BIG_IP),
    (r"support_id.*\d{10,}", WAFType.F5_BIG_IP),
    (r"Please consult with your administrator", WAFType.F5_BIG_IP),
    (r"Your support ID is", WAFType.F5_BIG_IP),
    (r"F5 Networks", WAFType.F5_BIG_IP),
    (r"Your request was blocked.*Barracuda", WAFType.BARRACUDA),
    (r"barra_counter_session", WAFType.BARRACUDA),
    (r"Barracuda Web Application Firewall", WAFType.BARRACUDA),
    (r"FortiGuard", WAFType.FORTIWEB),
    (r"\.fgd_icon", WAFType.FORTIWEB),
    (r"FortiWeb", WAFType.FORTIWEB),
    (r"fortigate", WAFType.FORTIWEB),
    (r"Generated by Wordfence", WAFType.WORDFENCE),
    (r"wordfence", WAFType.WORDFENCE),
    (r"wfwaf-", WAFType.WORDFENCE),
    (r"This response was generated by Wordfence", WAFType.WORDFENCE),
    (r"AWS WAF", WAFType.AWS_WAF),
    (r"<h1>403 ERROR</h1>.*The Amazon CloudFront distribution", WAFType.AWS_WAF),
    (r"Request blocked.*aws", WAFType.AWS_WAF),
    (r"awswaf", WAFType.AWS_WAF),
    (r"Fastly error: unknown domain", WAFType.FASTLY),
    (r"Fastly-Restarts", WAFType.FASTLY),
    (r"StackPath", WAFType.STACKPATH),
    (r"You performed an action that triggered.*StackPath", WAFType.STACKPATH),
    (r"wallarm", WAFType.WALLARM),
    (r"nginx-wallarm", WAFType.WALLARM),
    (r"Unauthorized Activity Has Been Detected.*Radware", WAFType.RADWARE),
    (r"radware", WAFType.RADWARE),
    (r"ns_af=", WAFType.CITRIX_NETSCALER),
    (r"Citrix.*Application Firewall", WAFType.CITRIX_NETSCALER),
    (r"NetScaler", WAFType.CITRIX_NETSCALER),
    (r"has been blocked in accordance with company policy", WAFType.PALO_ALTO),
    (r"Sophos UTM", WAFType.SOPHOS),
    (r"Protected by COMODO", WAFType.COMODO),
    (r"Shield Security", WAFType.SHIELD_SECURITY),
]

WAF_PROBE_PAYLOADS = [
    "<script>alert(1)</script>",
    "' OR 1=1--",
    "../../etc/passwd",
    "${7*7}",
    "{{7*7}}",
    "%0d%0aX-Injected: header",
    "() { :; }; /bin/bash -c 'cat /etc/passwd'",
]

WAF_BLOCK_STATUS_CODES = {403, 406, 429, 444, 451, 499, 503}


def _check_headers(headers: Dict[str, str]) -> Optional[WAFInfo]:
    detections: List[Tuple[WAFType, str, str]] = []

    for header_name, pattern, waf_type, confidence in HEADER_SIGNATURES:
        for key, value in headers.items():
            if key.lower() == header_name.lower() and value and re.search(pattern, value, re.IGNORECASE):
                detections.append((waf_type, confidence, f"Header {key}: {value[:100]}"))

    if not detections:
        return None

    confidence_order = {"high": 0, "medium": 1, "low": 2}
    detections.sort(key=lambda x: confidence_order.get(x[1], 3))

    primary = detections[0]
    additional = [d[2] for d in detections[1:] if d[0] == primary[0]]

    return WAFInfo(
        detected=True,
        waf_type=primary[0],
        confidence=primary[1],
        evidence=primary[2],
        additional_detections=additional,
    )


def _check_block_page(content: str, status_code: int = 200) -> Optional[WAFInfo]:
    for pattern, waf_type in BLOCK_PAGE_SIGNATURES:
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
            return WAFInfo(
                detected=True,
                waf_type=waf_type,
                confidence="high",
                evidence=f"Block page matched: {pattern[:60]}",
                blocks_payloads=status_code in WAF_BLOCK_STATUS_CODES,
            )
    return None


def _check_cookie_signatures(headers: Dict[str, str]) -> Optional[WAFInfo]:
    cookie_header = ""
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            cookie_header += value + "; "

    if not cookie_header:
        return None

    cookie_patterns = [
        (r"__cfduid|__cf_bm|cf_clearance", WAFType.CLOUDFLARE, "medium"),
        (r"incap_ses_|visid_incap_|_Incapsula_Resource", WAFType.IMPERVA, "high"),
        (r"BIGipServer|TS[a-zA-Z0-9]{3,8}=", WAFType.F5_BIG_IP, "medium"),
        (r"barra_counter_session|BNI__BARRACUDA", WAFType.BARRACUDA, "high"),
        (r"fortiwafsid", WAFType.FORTIWEB, "high"),
        (r"rbzid=", WAFType.REBLAZE, "high"),
        (r"ns_af=|citrix_ns_id|NSC_", WAFType.CITRIX_NETSCALER, "medium"),
        (r"X-SL-Session", WAFType.RADWARE, "high"),
        (r"wp-shield", WAFType.SHIELD_SECURITY, "medium"),
        (r"aws-waf-token", WAFType.AWS_WAF, "high"),
    ]

    for pattern, waf_type, confidence in cookie_patterns:
        if re.search(pattern, cookie_header, re.IGNORECASE):
            return WAFInfo(
                detected=True,
                waf_type=waf_type,
                confidence=confidence,
                evidence=f"Cookie pattern: {pattern[:50]}",
            )
    return None


def _merge_detections(
    header_result: Optional[WAFInfo],
    cookie_result: Optional[WAFInfo],
    probe_result: Optional[WAFInfo],
) -> Optional[WAFInfo]:
    results = [r for r in [header_result, cookie_result, probe_result] if r is not None]
    if not results:
        return None

    confidence_order = {"high": 0, "medium": 1, "low": 2}
    results.sort(key=lambda x: confidence_order.get(x.confidence, 3))

    best = results[0]
    for r in results[1:]:
        if r.waf_type == best.waf_type:
            best.additional_detections.append(r.evidence)
        elif r.confidence in ("high", "medium"):
            best.additional_detections.append(f"Also detected: {r.waf_type.value} ({r.evidence})")

    if any(r.blocks_payloads for r in results):
        best.blocks_payloads = True

    return best


@functools.lru_cache(maxsize=4096)
def detect_waf(url: str) -> WAFInfo:
    try:
        normal_response = http_requests.get(url)
    except Exception:
        return WAFInfo(detected=False, waf_type=WAFType.UNKNOWN, confidence="low", evidence="Connection failed")

    header_result = _check_headers(normal_response.headers)
    cookie_result = _check_cookie_signatures(normal_response.headers)

    if header_result and header_result.confidence == "high":
        merged = _merge_detections(header_result, cookie_result, None)
        if merged:
            LOGGER.info("WAF detected on %s: %s (passive)", url, merged.waf_type.value)
            return merged

    probe_result = None
    for probe_payload in WAF_PROBE_PAYLOADS:
        separator = "&" if "?" in url else "?"
        probe_url = f"{url}{separator}waf_test={probe_payload}"
        try:
            probe_response = http_requests.get(probe_url)
        except Exception:
            if header_result or cookie_result:
                result = _merge_detections(header_result, cookie_result, None)
                if result:
                    result.blocks_payloads = True
                    return result
            probe_result = WAFInfo(
                detected=True,
                waf_type=WAFType.UNKNOWN,
                confidence="low",
                evidence=f"Connection dropped on probe: {probe_payload[:30]}",
                blocks_payloads=True,
            )
            continue

        if (
            probe_response.status_code in WAF_BLOCK_STATUS_CODES
            and normal_response.status_code not in WAF_BLOCK_STATUS_CODES
        ):
            block_page_result = _check_block_page(probe_response.content, probe_response.status_code)
            if block_page_result:
                LOGGER.info("WAF detected on %s: %s (block page)", url, block_page_result.waf_type.value)
                merged = _merge_detections(header_result, cookie_result, block_page_result)
                if merged:
                    merged.blocks_payloads = True
                    return merged
                return block_page_result

            probe_header_result = _check_headers(probe_response.headers)
            if probe_header_result:
                probe_header_result.blocks_payloads = True
                merged = _merge_detections(header_result, cookie_result, probe_header_result)
                if merged:
                    merged.blocks_payloads = True
                    return merged

            probe_result = WAFInfo(
                detected=True,
                waf_type=WAFType.UNKNOWN,
                confidence="medium",
                evidence=f"Probe blocked with status {probe_response.status_code}",
                blocks_payloads=True,
            )
            break

        block_page_result = _check_block_page(probe_response.content, probe_response.status_code)
        if block_page_result:
            LOGGER.info("WAF detected on %s: %s (probe content)", url, block_page_result.waf_type.value)
            merged = _merge_detections(header_result, cookie_result, block_page_result)
            if merged:
                return merged
            return block_page_result

    merged = _merge_detections(header_result, cookie_result, probe_result)
    if merged:
        return merged

    return WAFInfo(detected=False, waf_type=WAFType.UNKNOWN, confidence="low", evidence="No WAF detected")
