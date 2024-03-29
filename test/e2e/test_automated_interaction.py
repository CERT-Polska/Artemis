import time
from test.e2e.base import BACKEND_URL, BaseE2ETestCase

import requests

from artemis.frontend import get_binds_that_can_be_disabled


class AutomatedInteractionTestCase(BaseE2ETestCase):
    def test_api_token_is_required(self) -> None:
        self.assertEqual(
            requests.post(
                BACKEND_URL + "api/add",
                {},
                headers={"Content-Type": "application/json", "X-API-Token": "invalid-api-token"},
            ).status_code,
            401,
        )
        self.assertEqual(
            requests.get(BACKEND_URL + "api/analyses", headers={"X-API-Token": "invalid-api-token"}).status_code, 401
        )
        self.assertEqual(
            requests.get(
                BACKEND_URL + "api/num-queued-tasks", headers={"X-API-Token": "invalid-api-token"}
            ).status_code,
            401,
        )
        self.assertEqual(
            requests.get(BACKEND_URL + "api/task-results", headers={"X-API-Token": "invalid-api-token"}).status_code,
            401,
        )

    def test_automated_interaction(self) -> None:
        self.assertEqual(
            requests.post(
                BACKEND_URL + "api/add",
                json={
                    "targets": ["test-smtp-server.artemis"],
                    "tag": "automated-interaction",
                    "disabled_modules": [
                        bind.identity
                        for bind in get_binds_that_can_be_disabled()
                        if bind.identity not in ["mail_dns_scanner", "classifier"]
                    ],
                },
                headers={"X-API-Token": "api-token"},
            ).json(),
            {"ok": True},
        )

        analyses = requests.get(BACKEND_URL + "api/analyses", headers={"X-API-Token": "api-token"}).json()
        self.assertEqual(len(analyses), 1)
        self.assertEqual(set(analyses[0].keys()), {"stopped", "target", "created_at", "id", "tag"})
        self.assertEqual(analyses[0]["stopped"], False)
        self.assertEqual(analyses[0]["target"], "test-smtp-server.artemis")
        self.assertEqual(analyses[0]["tag"], "automated-interaction")

        self.assertEqual(
            len(
                requests.get(BACKEND_URL + "api/num-queued-tasks", headers={"X-API-Token": "api-token"}).content.strip()
            ),
            1,
        )

        for i in range(100):
            task_results = requests.get(
                BACKEND_URL + "api/task-results?only_interesting=true", headers={"X-API-Token": "api-token"}
            ).json()

            if len(task_results) == 1:
                break

            time.sleep(1)

        self.assertEqual(
            len(
                requests.get(BACKEND_URL + "api/num-queued-tasks", headers={"X-API-Token": "api-token"}).content.strip()
            ),
            0,
        )

        task_results = requests.get(
            BACKEND_URL + "api/task-results?only_interesting=true", headers={"X-API-Token": "api-token"}
        ).json()
        self.assertEqual(len(task_results), 1)
        self.assertEqual(
            set(task_results[0].keys()),
            {
                "created_at",
                "receiver",
                "status_reason",
                "task",
                "status",
                "analysis_id",
                "id",
                "tag",
                "target_string",
                "result",
            },
        )
        self.assertEqual(task_results[0]["receiver"], "mail_dns_scanner")
        self.assertEqual(task_results[0]["status"], "INTERESTING")
        self.assertEqual(
            task_results[0]["status_reason"],
            "Found problems: Valid DMARC record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC to decrease the possibility of successful e-mail message spoofing.",
        )
        self.assertEqual(task_results[0]["tag"], "automated-interaction")
        self.assertEqual(task_results[0]["target_string"], "test-smtp-server.artemis")

        task_results = requests.get(
            BACKEND_URL + "api/task-results?search=should-not-exist", headers={"X-API-Token": "api-token"}
        ).json()
        self.assertEqual(len(task_results), 0)
