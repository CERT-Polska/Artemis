from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional
import secrets
from urllib.parse import urlparse

from karton.core import Task

from artemis.module_base import ArtemisBase
from artemis.binds import TaskStatus, TaskType
from artemis.task_utils import get_target_url


@dataclass
class CorsIssue:
    code: str
    severity: str
    title: str
    details: Dict


def _lower_headers(headers: Mapping[str, str]) -> Dict[str, str]:
    return {str(k).lower(): str(v).strip() for k, v in headers.items()}


def analyze_cors_headers(
    headers: Mapping[str, str],
    sent_origin: Optional[str] = None,
) -> List[CorsIssue]:

    h = _lower_headers(headers)

    acao = h.get("access-control-allow-origin")
    acc = h.get("access-control-allow-credentials")

    issues: List[CorsIssue] = []

    if not acao:
        return issues

    acc_true = (acc or "").lower() == "true"

    if acao == "*" and acc_true:
        issues.append(
            CorsIssue(
                "CORS_WILDCARD_WITH_CREDENTIALS",
                "high",
                "CORS wildcard with credentials",
                {"acao": acao},
            )
        )

    if acao.lower() == "null":
        issues.append(
            CorsIssue(
                "CORS_NULL_ORIGIN_ALLOWED",
                "medium",
                "CORS allows null origin",
                {"acao": acao},
            )
        )

    if sent_origin and acao == sent_origin:
        severity = "high" if acc_true else "medium"

        issues.append(
            CorsIssue(
                "CORS_ORIGIN_REFLECTION",
                severity,
                "CORS reflects Origin header",
                {"origin": sent_origin},
            )
        )

    return issues


def _random_origin(url: str) -> str:
    host = urlparse(url).hostname or "target"
    token = secrets.token_hex(6)
    return f"https://cors-test-{token}.{host}.invalid"


class CorsMisconfiguration(ArtemisBase):

    identity = "cors_misconfiguration"

    filters = [
        {"type": TaskType.URL.value},
        {"type": TaskType.WEBAPP.value},
    ]

    def run(self, current_task: Task):

        url = get_target_url(current_task)

        origin = _random_origin(url)

        response = self.http_get(
            url,
            headers={"Origin": origin},
        )

        issues = analyze_cors_headers(response.headers, sent_origin=origin)

        if issues:

            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.INTERESTING,
                status_reason="CORS misconfiguration detected",
                data={
                    "issues": [issue.__dict__ for issue in issues],
                },
            )

        else:

            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.OK,
            )


if __name__ == "__main__":
    CorsMisconfiguration().loop()