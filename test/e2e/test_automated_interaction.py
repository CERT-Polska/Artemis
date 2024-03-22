from test.e2e.base import BACKEND_URL, BaseE2ETestCase

import requests


class AutomatedInteractionTestCase(BaseE2ETestCase):
    def test_api_token_is_required(self) -> None:
        self.assertEqual(
            requests.post(
                BACKEND_URL + "/api/add",
                {},
                headers={"Content-Type": "application/json", "X-API-Token": "invalid-api-token"},
            ).status_code,
            401,
        )
        self.assertEqual(
            requests.get(BACKEND_URL + "/api/analyses", headers={"X-API-Token": "invalid-api-token"}).status_code, 401
        )
        self.assertEqual(
            requests.get(
                BACKEND_URL + "/api/num-queued-tasks", headers={"X-API-Token": "invalid-api-token"}
            ).status_code,
            401,
        )
        self.assertEqual(
            requests.get(BACKEND_URL + "/api/task-results", headers={"X-API-Token": "invalid-api-token"}).status_code,
            401,
        )

    def test_automated_interaction(self) -> None:
        self.assertEqual(
            requests.post(
                BACKEND_URL + "/api/add",
                {
                    "targets": ["test-smtp-server.artemis"],
                    "tag": "automated-interaction",
                    "disabled_modules": ["example", "humble"],
                },
                headers={"Content-Type": "application/json", "X-API-Token": "api-token"},
            ).json(),
            {"ok": True},
        )

        analyses = requests.get(BACKEND_URL + "/api/analyses", headers={"X-API-Token": "api-token"}).json()
        self.assertEqual(len(analyses), 1)
        self.assertEqual(set(analyses[0].keys()), {"stopped", "target", "created_at", "id", "tag", "task"})
        self.assertEqual(analyses[0]["stopped"], False)
        self.assertEqual(analyses[0]["target"], "test-smtp-server.artemis")
        self.assertEqual(analyses[0]["tag"], "automated-interaction")
        self.assertEqual(analyses[0]["task"]["payload"]["data"], "test-smtp-server.artemis")
