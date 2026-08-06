from test.e2e.base import BACKEND_URL, BaseE2ETestCase

import requests
from karton.core import Producer, Task
from karton.core.config import Config as KartonConfig

from artemis.db import DB


class DeduplicationE2ETestCase(BaseE2ETestCase):
    def test_module_does_not_process_same_task_twice(self) -> None:
        tag = "deduplication-test"
        target = "test-smtp-server.artemis"

        response = requests.post(
            BACKEND_URL + "api/add",
            json={
                "targets": [target],
                "tag": tag,
                "disabled_modules": [],
            },
            headers={"X-API-Token": "api-token"},
        )
        self.assertTrue(response.json().get("ok", False))

        self.wait_for_tasks_finished()

        db = DB()
        mail_dns_results = [
            r
            for r in db.get_paginated_task_results(0, 1000, []).data
            if r.get("task", {}).get("headers", {}).get("receiver") == "mail_dns_scanner" and r.get("tag") == tag
        ]
        self.assertEqual(len(mail_dns_results), 1, "Expected exactly 1 mail_dns_scanner result after first run")

        # Re-inject the same task into the Karton queue.
        stored_task = mail_dns_results[0]["task"]
        analysis_id = mail_dns_results[0]["analysis_id"]

        duplicate_task = Task(
            headers={k: v for k, v in stored_task["headers"].items() if k not in ("origin", "receiver", "status")},
            payload=stored_task.get("payload", {}),
            payload_persistent=stored_task.get("payload_persistent", {}),
            root_uid=analysis_id,
        )

        producer = Producer(config=KartonConfig(), identity="deduplication-test")
        producer.send_task(duplicate_task)

        self.wait_for_tasks_finished()

        mail_dns_results_after = [
            r
            for r in db.get_paginated_task_results(0, 1000, []).data
            if r.get("task", {}).get("headers", {}).get("receiver") == "mail_dns_scanner" and r.get("tag") == tag
        ]
        self.assertEqual(
            len(mail_dns_results_after),
            1,
            "Deduplication failed: mail_dns_scanner processed the same task twice",
        )
