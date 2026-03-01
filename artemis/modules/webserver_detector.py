#!/usr/bin/env python3
import re
from typing import Dict, Optional

from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class WebServerDetector(ArtemisBase):
    """
    Detects web server software and versions from HTTP headers.
    Analyzes the Server header to identify web servers like nginx, Apache,
    IIS, lighttpd, and their versions.
    """

    identity = "webserver_detector"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    # Common web server patterns
    SERVER_PATTERNS = [
        # nginx
        (r"nginx/([\d.]+)", "nginx"),
        (r"nginx", "nginx"),
        # Apache
        (r"Apache/([\d.]+)", "Apache"),
        (r"Apache", "Apache"),
        # Microsoft IIS
        (r"Microsoft-IIS/([\d.]+)", "Microsoft-IIS"),
        (r"Microsoft-IIS", "Microsoft-IIS"),
        # lighttpd
        (r"lighttpd/([\d.]+)", "lighttpd"),
        (r"lighttpd", "lighttpd"),
        # LiteSpeed
        (r"LiteSpeed/([\d.]+)", "LiteSpeed"),
        (r"LiteSpeed", "LiteSpeed"),
        # Caddy
        (r"Caddy/([\d.]+)", "Caddy"),
        (r"Caddy", "Caddy"),
        # Cherokee
        (r"Cherokee/([\d.]+)", "Cherokee"),
        (r"Cherokee", "Cherokee"),
        # Tomcat
        (r"Apache-Coyote/([\d.]+)", "Apache Tomcat"),
        # Jetty
        (r"Jetty\(([^\)]+)\)", "Jetty"),
        # Cloudflare
        (r"cloudflare", "cloudflare"),
    ]

    def _parse_server_header(self, server_header: str) -> Dict[str, Optional[str]]:
        """
        Parse Server header to extract web server name and version.

        Args:
            server_header: Value of the Server HTTP header

        Returns:
            Dictionary with server name, version, and additional components
        """
        if not server_header:
            return {}

        # Try to match known server patterns
        for pattern, server_name in self.SERVER_PATTERNS:
            match = re.search(pattern, server_header, re.IGNORECASE)
            if match:
                version = None
                if match.groups():
                    version = match.group(1)

                # Extract additional components (e.g., OS, modules)
                components = []
                # Look for parenthesized content like (Ubuntu) or (Win64)
                os_match = re.findall(r"\(([^)]+)\)", server_header)
                if os_match:
                    components.extend(os_match)

                return {
                    "name": server_name,
                    "version": version,
                    "components": components,
                    "raw_header": server_header,
                }

        # If no known pattern matches, treat entire value as custom server name
        # Extract first word as server name
        server_name = server_header.split()[0] if server_header else "Unknown"
        return {
            "name": server_name,
            "version": None,
            "components": [],
            "raw_header": server_header,
        }

    def _detect_webserver(self, response) -> Optional[Dict[str, Optional[str]]]:
        """
        Detect web server from HTTP response headers.

        Args:
            response: HTTP response object with headers

        Returns:
            Dictionary with server information or None if not detected
        """
        server_header = response.headers.get("Server", "")

        if not server_header:
            return None

        return self._parse_server_header(server_header)

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"web server detector scanning {url}")

        try:
            response = self.http_get(url, allow_redirects=True)
            server_info = self._detect_webserver(response)

            if server_info:
                # Format server information for status reason
                if server_info["version"]:
                    server_display = f"{server_info['name']}/{server_info['version']}"
                else:
                    server_display = server_info["name"]

                if server_info.get("components"):
                    components_str = ", ".join(server_info["components"])
                    server_display += f" ({components_str})"

                status = TaskStatus.INTERESTING
                status_reason = f"Detected web server: {server_display}"
            else:
                status = TaskStatus.OK
                status_reason = "No web server information detected"

            self.db.save_task_result(
                task=current_task,
                status=status,
                status_reason=status_reason,
                data={"server": server_info},
            )

        except Exception as e:
            self.log.error(f"Error detecting web server for {url}: {e}")
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.ERROR,
                status_reason=f"Error during web server detection: {str(e)}",
                data={"server": None},
            )


if __name__ == "__main__":
    WebServerDetector().loop()
