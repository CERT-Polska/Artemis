from __future__ import annotations

from typing import Any, Dict, List

from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.report import Report


class CookieSecurityReporter(Reporter):

    report_type = "cookie_security"

    template = "template_cookie_security.jinja2"

    def build_template_args(self, report: Report) -> Dict[str, Any]:

        additional = getattr(report, "additional_data", {}) or {}

        issues: List[Dict[str, Any]] = additional.get("issues", [])

        return {"issues": issues}