from test.e2e.base import BACKEND_URL, BaseE2ETestCase

import requests


class TaskPathTestCase(BaseE2ETestCase):
    def test_api_task_path_endpoint(self) -> None:
        """Test the /api/task/{task_uid}/path endpoint returns correct path"""
        self.submit_tasks(["test-domain.com"], "api-path-test")
        self.wait_for_tasks_finished()

        response = requests.get(f"{BACKEND_URL}api/task-results", headers={"X-API-Token": "api-token"})
        tasks = response.json()

        if tasks:
            task_uid = tasks[0]["task"]["uid"]

            # Test the API endpoint
            response = requests.get(f"{BACKEND_URL}api/task/{task_uid}/path", headers={"X-API-Token": "api-token"})
            self.assertEqual(response.status_code, 200)

            data = response.json()
            self.assertIn("path", data)
            self.assertIsInstance(data["path"], list)
            self.assertGreater(len(data["path"]), 0)

            # The path should start with a root task (no parent_uid)
            root_task = data["path"][0]
            root_task_data = root_task.get("task", {})
            if "parent_uid" in root_task_data:
                self.assertIsNone(root_task_data["parent_uid"])

            # The last task should be the requested one
            self.assertEqual(data["path"][-1]["id"], task_uid)
