import json
import re
import tempfile
import time
import zipfile
from test.e2e.base import BACKEND_URL, BaseE2ETestCase

import requests
from bs4 import BeautifulSoup

from artemis.utils import build_logger

LOGGER = build_logger(__name__)


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
                            "    <html>",
                            "        <head>",
                            '            <meta charset="UTF-8">',
                            "        </head>",
                            "        <style>",
                            "            ul {",
                            "                margin-top: 10px;",
                            "                margin-bottom: 10px;",
                            "            }",
                            "        </style>",
                            "        <body>",
                            "",
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
                            "",
                            "",
                            "        </body>",
                            "    </html>",
                            "",
                        ]
                    ).encode("ascii"),
                )

            with export.open("advanced/output.json", "r") as f:
                output_data = json.loads(f.read().decode("ascii"))
                self.assertEqual(
                    output_data["messages"]["test-smtp-server.artemis"]["reports"][0]["html"],
                    "\n".join(
                        [
                            "The following domains don't have properly configured e-mail sender verification mechanisms:        <ul>",
                            "<li>",
                            "                        test-smtp-server.artemis:",
                            "",
                            "                            Valid DMARC record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC to decrease the possibility of successful e-mail message spoofing.",
                            "                        ",
                            "                    </li>",
                            "</ul>",
                            "<p>",
                            "            These mechanisms greatly increase the chance that the recipient server will reject a spoofed message.",
                            "            Even if a domain is not used to send e-mails, SPF and DMARC records are needed to reduce the possibility to spoof e-mails.",
                            "        </p>",
                        ]
                    ),
                )

    def test_exporting_api(self) -> None:
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
                json={"skip_previously_exported": True, "language": "pl_PL", "tag": "exporting-api"},
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

        self.assertEqual(len(requests.get(BACKEND_URL + "api/exports", headers={"X-Api-Token": "api-token"}).json()), 1)
        self.assertEqual(
            len(requests.get(BACKEND_URL + "api/exports?tag_prefix=", headers={"X-Api-Token": "api-token"}).json()), 1
        )
        self.assertEqual(
            len(
                requests.get(
                    BACKEND_URL + "api/exports?tag_prefix=exporting-a", headers={"X-Api-Token": "api-token"}
                ).json()
            ),
            1,
        )
        self.assertEqual(
            len(
                requests.get(
                    BACKEND_URL + "api/exports?tag_prefix=exporting-b", headers={"X-Api-Token": "api-token"}
                ).json()
            ),
            0,
        )

        self.assertEqual(
            data[0].keys(),
            {
                "id",
                "created_at",
                "comment",
                "tag",
                "status",
                "language",
                "skip_previously_exported",
                "zip_url",
                "error",
                "alerts",
            },
        )

        if data[0]["status"] != "done":
            LOGGER.error("Invalid status for response: %s", repr(data))

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
            f.write(requests.get(BACKEND_URL + data[0]["zip_url"], headers={"X-Api-Token": "api-token"}).content)

        with zipfile.ZipFile(filename) as export:
            with export.open("messages/test-smtp-server.artemis.html", "r") as f:
                content = f.read()
                self.assertEqual(
                    content,
                    "\n".join(
                        [
                            "",
                            "    <html>",
                            "        <head>",
                            '            <meta charset="UTF-8">',
                            "        </head>",
                            "        <style>",
                            "            ul {",
                            "                margin-top: 10px;",
                            "                margin-bottom: 10px;",
                            "            }",
                            "        </style>",
                            "        <body>",
                            "",
                            "        <ol>",
                            "    <li>Następujące domeny nie mają poprawnie skonfigurowanych mechanizmów weryfikacji nadawcy wiadomości e-mail:        <ul>",
                            "                    <li>",
                            "                        test-smtp-server.artemis:",
                            "",
                            "                            Nie znaleziono poprawnego rekordu DMARC. Rekomendujemy używanie wszystkich trzech mechanizmów: SPF, DKIM i DMARC, aby zmniejszyć szansę, że sfałszowana wiadomość zostanie zaakceptowana przez serwer odbiorcy.",
                            "                        ",
                            "                    </li>",
                            "        </ul>",
                            "        <p>",
                            "            Wdrożenie tych mechanizmów znacząco zwiększy szansę, że serwer odbiorcy odrzuci sfałszowaną wiadomość e-mail z powyższych domen. W serwisie <a href='https://bezpiecznapoczta.cert.pl'>https://bezpiecznapoczta.cert.pl</a> można zweryfikować poprawność implementacji mechanizmów weryfikacji nadawcy poczty w Państwa domenie.<br/><br/>Więcej informacji o działaniu mechanizmów weryfikacji nadawcy można znaleźć pod adresem <a href='https://cert.pl/posts/2021/10/mechanizmy-weryfikacji-nadawcy-wiadomosci'>https://cert.pl/posts/2021/10/mechanizmy-weryfikacji-nadawcy-wiadomosci</a>.",
                            "            Nawet w przypadku domeny niesłużącej do wysyłki poczty rekordy SPF i DMARC są potrzebne w celu ograniczenia możliwości podszycia się pod nią. Odpowiednia konfiguracja jest opisana w powyższym artykule.",
                            "        </p>",
                            "    </li>",
                            "        </ol>",
                            "",
                            "",
                            "        </body>",
                            "    </html>",
                            "",
                        ]
                    ).encode("utf-8"),
                )

    def test_tag_export_gui(self) -> None:
        self.submit_tasks_with_modules_enabled(
            ["test-smtp-server.artemis"], "saving_tag-gui", ["mail_dns_scanner", "classifier"]
        )

        with requests.Session() as s:
            data = s.get(BACKEND_URL + "export").content
            soup = BeautifulSoup(data, "html.parser")

            option_values = [option.text for option in soup.select("select option")]

        self.assertTrue("saving_tag-gui" in option_values)

    def test_reporting_export_tag_gui(self) -> None:
        tag = "reporting_export_tag-gui"
        self.submit_tasks_with_modules_enabled(["test-smtp-server.artemis"], tag, ["mail_dns_scanner", "classifier"])

        with requests.Session() as s:
            data = s.get(BACKEND_URL + "export").content
            soup = BeautifulSoup(data, "html.parser")
            csrf_token = soup.find("input", {"name": "csrf_token"})["value"]  # type: ignore

            s.post(
                BACKEND_URL + "export",
                data={
                    "csrf_token": csrf_token,
                    "comment": "something",
                    "language": "en_US",
                    "tag": tag,
                    "skip_previously_exported": "No",
                },
            )

        with requests.Session() as s:
            data = s.get(BACKEND_URL + "exports").content
            soup = BeautifulSoup(data, "html.parser")
            t_body = soup.find_all(id="task_list")[0].tbody

            for tr in t_body.find_all("tr"):
                package = tr.find_all("td")[1]
                print(package.text)

        self.assertTrue(tag == package.text)
