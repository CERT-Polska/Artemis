import time
from test.e2e.base import BACKEND_URL, BaseE2ETestCase

import requests
from bs4 import BeautifulSoup


class ExportingTestCase(BaseE2ETestCase):
    def test_exporting_gui(self) -> None:
        self.submit_tasks_with_modules_enabled(
            ["test-smtp-server.artemis"], "exporting-gui", ["mail_dns_scanner", "classifier"]
        )

        for i in range(100):
            task_results = requests.get(
                BACKEND_URL + "api/task-results?only_interesting=true", headers={"X-API-Token": "api-token"}
            ).json()

            if len(task_results) == 1:
                break

            time.sleep(1)

        with requests.Session() as s:
            data = s.get(BACKEND_URL + "export").content
            soup = BeautifulSoup(data, "html.parser")
            csrf_token = soup.find("input", {"name": "csrf_token"})["value"]  # type: ignore

            response = s.post(
                BACKEND_URL + "export",
                data={
                    "csrf_token": csrf_token,
                    "tag": "exporting-gui",
                    "comment": "",
                    "skip_previously_exported": "no",
                    "language": "en_US",
                },
            )
            response.raise_for_status()
            self.assertEqual(response.url, "/exports")

        for i in range(100):
            task_results = requests.get(
                BACKEND_URL + "api/task-results?only_interesting=true", headers={"X-API-Token": "api-token"}
            ).json()

            if len(task_results) == 1:
                break
            data = s.get(BACKEND_URL + "exports").content
            assert (
                b'<span class="badge bg-warning">pending</span>' in data
                or b'<span class="badge bg-success">done</span>' in data
            )

            if b'<span class="badge bg-success">done</span>' in data:
                break

            time.sleep(1)

        print(data)
