from __future__ import annotations

from typing import Any, Dict, List

from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.report import Report


class CorsMisconfigurationReporter(Reporter):

    report_type = "cors_misconfiguration"

    template = "template_cors_misconfiguration.jinja2"

    def build_template_args(self, report: Report) -> Dict[str, Any]:

        additional = getattr(report, "additional_data", {}) or {}

        issues: List[Dict[str, Any]] = additional.get("issues", [])

        return {"issues": issues}