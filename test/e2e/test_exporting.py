import re
import tempfile
import time
import zipfile
from test.e2e.base import BACKEND_URL, BaseE2ETestCase

import requests
from bs4 import BeautifulSoup


class ExportingTestCase(BaseE2ETestCase):
    def test_exporting_gui(self) -> None:
        self.maxDiff=None
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
            self.assertEqual(response.url, "http://web:5000/exports")

        for i in range(500):
            data = s.get(BACKEND_URL + "exports").content
            assert (
                b'<span class="badge bg-warning">pending</span>' in data
                or b'<span class="badge bg-success">done</span>' in data
            )

            if b'<span class="badge bg-success">done</span>' in data:
                break

            time.sleep(1)

        m = re.search('href="/(export/download-zip/[0-9]*)"', data.decode("utf-8"))
        assert m is not None
        (path,) = m.groups(1)
        filename = tempfile.mktemp()

        with open(filename, "wb") as f:
            f.write(requests.get(BACKEND_URL + str(path)).content)

        with zipfile.ZipFile(filename) as export:
            with export.open("messages/test-smtp-server.artemis.html", "r") as f:
                content = f.read()
                self.assertEqual(
                    content,
                    "\n".join(
                        [
                            "",
                            "",
                            "<html>",
                            "    <head>",
                            '        <meta charset="UTF-8">',
                            "    </head>",
                            "    <style>",
                            "        ul {",
                            "            margin-top: 10px;",
                            "            margin-bottom: 10px;",
                            "        }",
                            "    </style>",
                            "    <body>",
                            "        <ol>",
                            "    <li>The following domains don't have properly configured e-mail sender verification mechanisms:        <ul>",
                            "                    <li>",
                            "                        test-smtp-server.artemis:",
                            "",
                            "                            Valid DMARC record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC to decrease the possibility of successful e-mail message spoofing.",
                            "                        ",
                            "                    </li>",
                            "        </ul>",
                            "        <p>",
                            "            These mechanisms greatly increase the chance that the recipient server will reject a spoofed message.",
                            "            Even if a domain is not used to send e-mails, SPF and DMARC records are needed to reduce the possibility to spoof e-mails.",
                            "        </p>",
                            "    </li>",
                            "        </ol>",
                            "    </body>",
                            "</html>",
                            "",
                        ]
                    ),
                )

    def test_exporting_api(self) -> None:
        self.maxDiff=None
        self.submit_tasks_with_modules_enabled(
            ["test-smtp-server.artemis"], "exporting-api", ["mail_dns_scanner", "classifier"]
        )

        for i in range(100):
            task_results = requests.get(
                BACKEND_URL + "api/task-results?only_interesting=true", headers={"X-API-Token": "api-token"}
            ).json()

            if len(task_results) == 1:
                break

            time.sleep(1)

        self.assertEqual(requests.get(BACKEND_URL + "api/exports", headers={"X-Api-Token": "api-token"}).json(), [])
        self.assertEqual(
            requests.post(
                BACKEND_URL + "api/export",
                data={"skip_previously_exported": True, "language": "pl_PL"},
                headers={"X-Api-Token": "api-token"},
            ).json(),
            {"ok": True},
        )

        for i in range(500):
            data = requests.get(BACKEND_URL + "api/exports", headers={"X-Api-Token": "api-token"}).json()
            assert len(data) == 1
            if data[0]["zip_url"]:
                break

            time.sleep(1)

        self.assertEqual(
            data[0].keys(),
            {"id", "created_at", "comment", "tag", "status", "language", "skip_previously_exported", "zip_url", "error", "alerts"},
        )

        self.assertEqual(
            data[0]["status"],
            "done",
        )
        self.assertEqual(
            data[0]["language"],
            "pl_PL",
        )

        filename = tempfile.mktemp()

        with open(filename, "wb") as f:
            f.write(requests.get(BACKEND_URL + data[0]["export_url"], headers={"X-Api-Token": "api-token"}).content)

        with zipfile.ZipFile(filename) as export:
            with export.open("messages/test-smtp-server.artemis.html", "r") as f:
                content = f.read()
                self.assertEqual(
                    content,
                    "\n".join(
                        [
                            "",
                            "",
                            "<html>",
                            "    <head>",
                            '        <meta charset="UTF-8">',
                            "    </head>",
                            "    <style>",
                            "        ul {",
                            "            margin-top: 10px;",
                            "            margin-bottom: 10px;",
                            "        }",
                            "    </style>",
                            "    <body>",
                            "        <ol>",
                            "    <li>The following domains don't have properly configured e-mail sender verification mechanisms:        <ul>",
                            "                    <li>",
                            "                        test-smtp-server.artemis:",
                            "",
                            "                            Valid DMARC record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC to decrease the possibility of successful e-mail message spoofing.",
                            "                        ",
                            "                    </li>",
                            "        </ul>",
                            "        <p>",
                            "            These mechanisms greatly increase the chance that the recipient server will reject a spoofed message.",
                            "            Even if a domain is not used to send e-mails, SPF and DMARC records are needed to reduce the possibility to spoof e-mails.",
                            "        </p>",
                            "    </li>",
                            "        </ol>",
                            "    </body>",
                            "</html>",
                            "",
                        ]
                    ),
                )
