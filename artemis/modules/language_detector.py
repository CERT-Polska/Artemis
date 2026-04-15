#!/usr/bin/env python3
import re
from typing import Dict, List, Optional

from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class LanguageDetector(ArtemisBase):
    """
    Detects programming languages and their versions from HTTP headers.
    Analyzes X-Powered-By, Server, and other HTTP headers to identify
    languages like PHP, Python, ASP.NET, Perl, and their versions.
    """

    identity = "language_detector"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    # Patterns for detecting languages and versions
    LANGUAGE_PATTERNS = [
        # PHP detection
        (r"PHP/([\d.]+(?:-[\w.]+)?)", "PHP"),
        (r"PHP", "PHP"),
        # Python detection
        (r"Python/([\d.]+(?:-[\w.]+)?)", "Python"),
        # Perl detection
        (r"Perl/([\d.]+(?:-[\w.]+)?)", "Perl"),
        (r"mod_perl/([\d.]+)", "mod_perl"),
        # ASP.NET detection
        (r"ASP\.NET", "ASP.NET"),
        # Ruby detection
        (r"Ruby/([\d.]+(?:-[\w.]+)?)", "Ruby"),
        (r"Phusion Passenger/([\d.]+)", "Passenger/Ruby"),
        # Node.js detection
        (r"Node\.js/([\d.]+(?:-[\w.]+)?)", "Node.js"),
    ]

    def _extract_version(self, text: str, pattern: str) -> Optional[str]:
        """Extract version number from text using regex pattern"""
        match = re.search(pattern, text, re.IGNORECASE)
        if match and match.groups():
            return match.group(1)
        return None

    def _detect_languages(self, response) -> List[Dict[str, Optional[str]]]:
        """
        Detect programming languages from HTTP response headers.

        Args:
            response: HTTP response object with headers

        Returns:
            List of dictionaries with language name and version
        """
        languages = []
        detected_languages = set()

        # Headers to check for language information
        headers_to_check = [
            "X-Powered-By",
            "Server",
            "X-AspNet-Version",
            "X-Runtime",
        ]

        for header_name in headers_to_check:
            header_value = response.headers.get(header_name, "")
            if not header_value:
                continue

            for pattern, language_name in self.LANGUAGE_PATTERNS:
                match = re.search(pattern, header_value, re.IGNORECASE)
                if match:
                    # Avoid duplicates
                    if language_name in detected_languages:
                        continue

                    detected_languages.add(language_name)
                    version = None

                    # Try to extract version if pattern includes a capture group
                    if match.groups():
                        version = match.group(1)

                    languages.append(
                        {
                            "name": language_name,
                            "version": version,
                            "header": header_name,
                            "raw_value": header_value,
                        }
                    )

        return languages

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"language detector scanning {url}")

        try:
            response = self.http_get(url, allow_redirects=True)
            languages = self._detect_languages(response)

            if languages:
                # Format language information for status reason
                language_info = []
                for lang in languages:
                    if lang["version"]:
                        language_info.append(f"{lang['name']}/{lang['version']}")
                    else:
                        language_info.append(lang["name"])

                status = TaskStatus.INTERESTING
                status_reason = f"Detected programming languages: {', '.join(language_info)}"
            else:
                status = TaskStatus.OK
                status_reason = "No programming languages detected"

            self.db.save_task_result(
                task=current_task,
                status=status,
                status_reason=status_reason,
                data={"languages": languages},
            )

        except Exception as e:
            self.log.error(f"Error detecting languages for {url}: {e}")
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.ERROR,
                status_reason=f"Error during language detection: {str(e)}",
                data={"languages": []},
            )


if __name__ == "__main__":
    LanguageDetector().loop()
