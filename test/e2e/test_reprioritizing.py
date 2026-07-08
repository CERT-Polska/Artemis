from test.e2e.base import BACKEND_URL, BaseE2ETestCase
from typing import Dict

import requests
from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig
from karton.core.inspect import KartonState
from karton.core.task import TaskPriority as KartonTaskPriority
from karton.core.task import TaskState

from artemis.prioritizer.prioritizer import reprioritize_analyses

API_TOKEN = "api-token"
VALID_HEADERS: Dict[str, str] = {"X-API-Token": API_TOKEN}


class ReprioritizingTestCase(BaseE2ETestCase):
    def test_reprioritize_analysis_via_api(self) -> None:
        self.submit_tasks_with_modules_enabled(
            ["test-smtp-server.artemis"], "reprioritize-api", ["mail_dns_scanner", "classifier"]
        )

        analyses = requests.get(BACKEND_URL + "api/analyses?tag=reprioritize-api", headers=VALID_HEADERS).json()

        self.assertGreater(len(analyses), 0)

        analysis = analyses[0]
        analysis_id = analysis["id"]
        print(analysis)

        self.assertEqual(analysis["priority"], "normal")

        response = requests.get(
            BACKEND_URL + f"api/analyses/reprioritize/{analysis_id}?new_priority=high",
            headers=VALID_HEADERS,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True})

        analyses_after = requests.get(BACKEND_URL + "api/analyses?tag=reprioritize-api", headers=VALID_HEADERS).json()

        for a in analyses_after:
            if a["id"] == analysis_id:
                self.assertEqual(a["desired_priority"], "high")

    def test_reprioritize_analysis_invalid_priority(self) -> None:
        self.submit_tasks_with_modules_enabled(
            ["test-smtp-server.artemis"], "reprioritize-invalid", ["mail_dns_scanner", "classifier"]
        )

        analyses = requests.get(BACKEND_URL + "api/analyses?tag=reprioritize-invalid", headers=VALID_HEADERS).json()

        self.assertGreater(len(analyses), 0)

        analysis_id = analyses[0]["id"]

        response = requests.get(
            BACKEND_URL + f"api/analyses/reprioritize/{analysis_id}?new_priority=invalid",
            headers=VALID_HEADERS,
        )
        self.assertNotEqual(response.status_code, 200)

    def test_reprioritize_nonexistent_analysis(self) -> None:
        response = requests.get(
            BACKEND_URL + "api/analyses/reprioritize/nonexistent-id?new_priority=high",
            headers=VALID_HEADERS,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True})

    def test_reprioritize_without_api_token(self) -> None:
        invalid_headers: Dict[str, str] = {"X-API-Token": "wrong-token"}
        response = requests.get(
            BACKEND_URL + "api/analyses/reprioritize/some-id?new_priority=high",
            headers=invalid_headers,
        )
        self.assertEqual(response.status_code, 401)

    def test_reprioritize_end_to_end_high(self) -> None:
        self.submit_tasks_with_modules_enabled(
            ["test-smtp-server.artemis"], "reprioritize-e2e-high", ["mail_dns_scanner", "classifier"]
        )

        analyses = requests.get(BACKEND_URL + "api/analyses?tag=reprioritize-e2e-high", headers=VALID_HEADERS).json()
        analysis_id = analyses[0]["id"]
        print(analyses)

        self.assertEqual(analyses[0]["priority"], "normal")

        response = requests.get(
            BACKEND_URL + f"api/analyses/reprioritize/{analysis_id}?new_priority=high",
            headers=VALID_HEADERS,
        )
        self.assertEqual(response.status_code, 200)

        reprioritize_analyses()

        analyses = requests.get(BACKEND_URL + "api/analyses?tag=reprioritize-e2e-high", headers=VALID_HEADERS).json()
        target = next((a for a in analyses if a["id"] == analysis_id), None)
        self.assertEqual(target["priority"], "high")  # type: ignore
        self.assertEqual(target["desired_priority"], "high")  # type: ignore

        backend = KartonBackend(config=KartonConfig())
        state = KartonState(backend=backend)
        if analysis_id in state.analyses:
            for task in state.analyses[analysis_id].tasks:
                if task.status in [TaskState.SPAWNED, TaskState.DECLARED]:
                    self.assertEqual(task.priority, KartonTaskPriority.HIGH)

    def test_reprioritize_end_to_end_low(self) -> None:
        self.submit_tasks_with_modules_enabled(
            ["test-smtp-server.artemis"], "reprioritize-e2e-low", ["mail_dns_scanner", "classifier"]
        )

        analyses = requests.get(BACKEND_URL + "api/analyses?tag=reprioritize-e2e-low", headers=VALID_HEADERS).json()
        analysis_id = analyses[0]["id"]

        self.assertEqual(analyses[0]["priority"], "normal")

        response = requests.get(
            BACKEND_URL + f"api/analyses/reprioritize/{analysis_id}?new_priority=low",
            headers=VALID_HEADERS,
        )
        self.assertEqual(response.status_code, 200)

        reprioritize_analyses()

        analyses = requests.get(BACKEND_URL + "api/analyses?tag=reprioritize-e2e-low", headers=VALID_HEADERS).json()
        target = next((a for a in analyses if a["id"] == analysis_id), None)
        self.assertEqual(target["priority"], "low")  # type: ignore
        self.assertEqual(target["desired_priority"], "low")  # type: ignore

    def test_reprioritize_queue_migration(self) -> None:
        self.submit_tasks_with_modules_enabled(
            ["test-smtp-server.artemis"], "reprioritize-queue", ["mail_dns_scanner", "classifier"]
        )

        analyses = requests.get(BACKEND_URL + "api/analyses?tag=reprioritize-queue", headers=VALID_HEADERS).json()
        analysis_id = analyses[0]["id"]

        response = requests.get(
            BACKEND_URL + f"api/analyses/reprioritize/{analysis_id}?new_priority=high",
            headers=VALID_HEADERS,
        )
        self.assertEqual(response.status_code, 200)

        reprioritize_analyses()

        analyses = requests.get(BACKEND_URL + "api/analyses?tag=reprioritize-queue", headers=VALID_HEADERS).json()
        target = next((a for a in analyses if a["id"] == analysis_id), None)
        self.assertEqual(target["priority"], "high")  # type: ignore

        state = KartonState(backend=KartonBackend(config=KartonConfig()))
        if analysis_id in state.analyses:
            pending_tasks = [t for t in state.analyses[analysis_id].tasks if t.status.value in ["SPAWNED", "DECLARED"]]
            for task in pending_tasks:
                self.assertEqual(task.priority, KartonTaskPriority.HIGH)
