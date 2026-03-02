#!/usr/bin/env python3
import re
from typing import Any, Dict, List, Optional, Tuple

from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url

VERSION_PATTERN = re.compile(r"^([\w\s.!-]+?)(?:/(\d[\d.]*))?(?:\s+\((.+)\))?$")

HEADERS_WEB_SERVER = ["Server"]
HEADERS_LANGUAGE = ["X-Powered-By"]
HEADERS_FRAMEWORK = ["X-AspNet-Version", "X-AspNetMvc-Version"]
HEADERS_GENERATOR = ["X-Generator"]

ALL_INFO_HEADERS = HEADERS_WEB_SERVER + HEADERS_LANGUAGE + HEADERS_FRAMEWORK + HEADERS_GENERATOR

KNOWN_WEB_SERVERS = {
    "apache",
    "nginx",
    "lighttpd",
    "litespeed",
    "iis",
    "caddy",
    "openresty",
    "tomcat",
    "jetty",
    "gunicorn",
    "uvicorn",
    "envoy",
    "traefik",
    "cherokee",
    "tengine",
    "cowboy",
}

KNOWN_LANGUAGES = {
    "php",
    "asp.net",
    "perl",
    "python",
    "ruby",
    "java",
    "node.js",
    "express",
    "servlet",
    "jsp",
    "coldfusion",
}


def parse_product_token(raw_value: str) -> Tuple[str, Optional[str], Optional[str]]:
    """Parse an HTTP product token like 'Apache/2.4.53 (Ubuntu)' into (name, version, detail)."""
    match = VERSION_PATTERN.match(raw_value.strip())
    if match:
        return match.group(1).strip(), match.group(2), match.group(3)
    return raw_value.strip(), None, None


def classify_header(header_name: str, raw_value: str) -> Dict[str, Any]:
    name, version, detail = parse_product_token(raw_value)
    entry: Dict[str, Any] = {"name": name, "raw": raw_value}
    if version:
        entry["version"] = version
    if detail:
        entry["detail"] = detail

    if header_name in HEADERS_WEB_SERVER:
        entry["category"] = "web_server"
    elif header_name in HEADERS_LANGUAGE:
        name_lower = name.lower()
        if any(lang in name_lower for lang in KNOWN_LANGUAGES):
            entry["category"] = "programming_language"
        else:
            entry["category"] = "framework"
    elif header_name in HEADERS_FRAMEWORK:
        entry["category"] = "framework"
    elif header_name in HEADERS_GENERATOR:
        entry["category"] = "generator"
    else:
        entry["category"] = "other"

    return entry


def extract_server_info(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """Extract all server/language/framework info from HTTP response headers."""
    results: List[Dict[str, Any]] = []

    for header_name in ALL_INFO_HEADERS:
        raw_value = headers.get(header_name)
        if not raw_value:
            continue

        for part in raw_value.split(","):
            part = part.strip()
            if not part:
                continue
            entry = classify_header(header_name, part)
            entry["header"] = header_name
            results.append(entry)

    return results


def build_status_reason(detected: List[Dict[str, Any]]) -> str:
    parts: List[str] = []
    for item in detected:
        version_str = f" {item['version']}" if item.get("version") else ""
        parts.append(f"{item['name']}{version_str} (via {item['header']})")
    return "Server/technology version disclosure: " + ", ".join(parts)


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class ServerInfo(ArtemisBase):
    """
    Identifies web server software, programming language, and framework versions
    from HTTP response headers (Server, X-Powered-By, X-AspNet-Version, X-Generator).

    Version disclosure is a low-severity information leak (CWE-200) that helps
    attackers map the technology stack and find version-specific vulnerabilities.
    """

    identity = "server_info"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"server_info scanning {url}")

        response = self.http_get(url, allow_redirects=True)
        detected = extract_server_info(dict(response.headers))

        if detected:
            status = TaskStatus.INTERESTING
            status_reason = build_status_reason(detected)
        else:
            status = TaskStatus.OK
            status_reason = None

        raw_headers = {
            h: response.headers.get(h)
            for h in ALL_INFO_HEADERS
            if response.headers.get(h)
        }

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={
                "detected": detected,
                "raw_headers": raw_headers,
                "url": url,
            },
        )


if __name__ == "__main__":
    ServerInfo().loop()
