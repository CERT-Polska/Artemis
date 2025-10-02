import re
from typing import Any, Dict, List
from packaging import version

from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url


# Known vulnerable versions for common JavaScript libraries
# Based on CVEs and security advisories
VULNERABLE_VERSIONS = {
    "jQuery": {
        # CVE-2020-11023: jQuery before 3.5.0
        "max_safe": "3.5.0",
        "cve": "CVE-2020-11023",
        "description": "XSS vulnerability in jQuery HTML manipulation",
    },
    "AngularJS": {
        # CVE-2020-7676: AngularJS before 1.8.0
        "max_safe": "1.8.0",
        "cve": "CVE-2020-7676",
        "description": "XSS vulnerability in AngularJS",
    },
    "Bootstrap": {
        # CVE-2019-8331: Bootstrap before 4.3.1
        "max_safe": "4.3.1",
        "cve": "CVE-2019-8331",
        "description": "XSS vulnerability in Bootstrap data-target attribute",
    },
}

# Regex patterns for detecting JavaScript libraries
LIBRARY_PATTERNS = [
    # jQuery patterns
    {
        "name": "jQuery",
        "patterns": [
            r"jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js",
            r"jQuery\s+v?(\d+\.\d+\.\d+)",  # Matches inline comments like /*! jQuery v3.3.1 */
            r"jquery/(\d+\.\d+\.\d+)/",
        ],
    },
    # React patterns
    {
        "name": "React",
        "patterns": [
            r"react[.-](\d+\.\d+\.\d+)(?:\.min)?\.js",
            r"react@(\d+\.\d+\.\d+)",
            r"react/(\d+\.\d+\.\d+)/",
        ],
    },
    # Vue.js patterns
    {
        "name": "Vue.js",
        "patterns": [
            r"vue[.-](\d+\.\d+\.\d+)(?:\.min)?\.js",
            r"vue@(\d+\.\d+\.\d+)",
            r"vue/(\d+\.\d+\.\d+)/",
        ],
    },
    # AngularJS patterns
    {
        "name": "AngularJS",
        "patterns": [
            r"angular(?:js)?[.-](\d+\.\d+\.\d+)(?:\.min)?\.js",
            r"angularjs/(\d+\.\d+\.\d+)/",
        ],
    },
    # Bootstrap patterns
    {
        "name": "Bootstrap",
        "patterns": [
            r"bootstrap[.-](\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)",
            r"bootstrap@(\d+\.\d+\.\d+)",
            r"bootstrap/(\d+\.\d+\.\d+)/",
        ],
    },
    # Lodash patterns
    {
        "name": "Lodash",
        "patterns": [
            r"lodash[.-](\d+\.\d+\.\d+)(?:\.min)?\.js",
            r"lodash@(\d+\.\d+\.\d+)",
            r"lodash/(\d+\.\d+\.\d+)/",
        ],
    },
]


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class JSLibraryScanner(ArtemisBase):
    """
    Scans web pages for JavaScript libraries and detects vulnerable versions.
    Identifies popular libraries (jQuery, React, Angular, Vue.js, etc.) and checks
    them against known CVEs and security vulnerabilities.
    """

    identity = "js_library_scanner"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _detect_libraries(self, html_content: str) -> List[Dict[str, Any]]:
        """
        Detect JavaScript libraries and their versions from HTML content.

        Args:
            html_content: The HTML content to scan

        Returns:
            List of detected libraries with name, version, and vulnerability info
        """
        detected = []
        seen_libraries = set()  # Track library+version to avoid duplicates

        for library_info in LIBRARY_PATTERNS:
            library_name = library_info["name"]

            for pattern in library_info["patterns"]:
                matches = re.finditer(pattern, html_content, re.IGNORECASE)

                for match in matches:
                    detected_version = match.group(1)

                    # Avoid duplicate entries
                    lib_key = f"{library_name}:{detected_version}"
                    if lib_key in seen_libraries:
                        continue
                    seen_libraries.add(lib_key)

                    # Check if version is vulnerable
                    is_vulnerable = False
                    vulnerability_info = None

                    if library_name in VULNERABLE_VERSIONS:
                        vuln_data = VULNERABLE_VERSIONS[library_name]
                        try:
                            if version.parse(detected_version) < version.parse(vuln_data["max_safe"]):
                                is_vulnerable = True
                                vulnerability_info = {
                                    "cve": vuln_data["cve"],
                                    "description": vuln_data["description"],
                                    "min_safe_version": vuln_data["max_safe"],
                                }
                        except Exception:
                            # If version parsing fails, skip vulnerability check
                            pass

                    library_entry = {
                        "name": library_name,
                        "version": detected_version,
                        "vulnerable": is_vulnerable,
                    }

                    if vulnerability_info:
                        library_entry["vulnerability"] = vulnerability_info

                    detected.append(library_entry)

        # Sort by name for consistent output
        detected.sort(key=lambda x: (x["name"], x["version"]))

        return detected

    def run(self, current_task: Task) -> None:
        """
        Scan the target URL for JavaScript libraries and check for vulnerabilities.

        Args:
            current_task: The Karton task containing target information
        """
        url = get_target_url(current_task)
        self.log.info(f"Scanning {url} for JavaScript libraries")

        try:
            # Fetch the web page
            response = self.http_get(url)
            html_content = response.text

            # Detect libraries
            detected_libraries = self._detect_libraries(html_content)

            # Determine task status based on findings
            vulnerable_libraries = [lib for lib in detected_libraries if lib.get("vulnerable", False)]

            if vulnerable_libraries:
                status = TaskStatus.INTERESTING
                vuln_descriptions = []
                for lib in vulnerable_libraries:
                    vuln_info = lib.get("vulnerability", {})
                    cve = vuln_info.get("cve", "")
                    vuln_descriptions.append(f"{lib['name']} {lib['version']} ({cve})")

                status_reason = f"Found vulnerable JavaScript libraries: {', '.join(vuln_descriptions)}"
            elif detected_libraries:
                status = TaskStatus.OK
                status_reason = f"Found {len(detected_libraries)} JavaScript libraries, none with known vulnerabilities"
            else:
                status = TaskStatus.OK
                status_reason = "No JavaScript libraries detected"

            self.db.save_task_result(
                task=current_task,
                status=status,
                status_reason=status_reason,
                data={"detected_libraries": detected_libraries},
            )

        except Exception as e:
            self.log.error(f"Error scanning {url}: {e}")
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.ERROR,
                status_reason=f"Error scanning for JavaScript libraries: {str(e)}",
                data={"error": str(e)},
            )


if __name__ == "__main__":
    JSLibraryScanner().loop()
