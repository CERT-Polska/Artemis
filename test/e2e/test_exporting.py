import re
import tempfile
import time
import zipfile
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
                print(
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
                        ]
                    ),
                )
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
                print(
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
                            "    <li>NastÄ\x99pujÄ\x85ce domeny nie majÄ\x85 poprawnie skonfigurowanych mechanizmÃ³w weryfikacji nadawcy wiadomoÅ\x9bci e-mail:        <ul>",
                            "                    <li>",
                            "                        test-smtp-server.artemis:",
                            "",
                            "                            Nie znaleziono poprawnego rekordu DMARC. Rekomendujemy uÅ¼ywanie wszystkich trzech mechanizmÃ³w: SPF, DKIM i DMARC, aby zmniejszyÄ\x87 szansÄ\x99, Å¼e sfaÅ\x82szowana wiadomoÅ\x9bÄ\x87 zostanie zaakceptowana przez serwer odbiorcy.",
                            "                        ",
                            "                    </li>",
                            "        </ul>",
                            "        <p>",
                            "            WdroÅ¼enie tych mechanizmÃ³w znaczÄ\x85co zwiÄ\x99kszy szansÄ\x99, Å¼e serwer odbiorcy odrzuci sfaÅ\x82szowanÄ\x85 wiadomoÅ\x9bÄ\x87 e-mail z powyÅ¼szych domen. W serwisie <a href='https://bezpiecznapoczta.cert.pl'>https://bezpiecznapoczta.cert.pl</a> moÅ¼na zweryfikowaÄ\x87 poprawnoÅ\x9bÄ\x87 implementacji mechanizmÃ³w weryfikacji nadawcy poczty w PaÅ\x84stwa domenie.<br/><br/>WiÄ\x99cej informacji o dziaÅ\x82aniu mechanizmÃ³w weryfikacji nadawcy moÅ¼na znaleÅºÄ\x87 pod adresem <a href='https://cert.pl/posts/2021/10/mechanizmy-weryfikacji-nadawcy-wiadomosci'>https://cert.pl/posts/2021/10/mechanizmy-weryfikacji-nadawcy-wiadomosci</a>.",
                            "            Nawet w przypadku domeny niesÅ\x82uÅ¼Ä\x85cej do wysyÅ\x82ki poczty rekordy SPF i DMARC sÄ\x85 potrzebne w celu ograniczenia moÅ¼liwoÅ\x9bci podszycia siÄ\x99 pod niÄ\x85. Odpowiednia konfiguracja jest opisana w powyÅ¼szym artykule.",
                            "        </p>",
                            "    </li>",
                            "        </ol>",
                            "    </body>",
                            "</html>",
                        ]
                    ),
                )
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
                            "    <li>NastÄ\x99pujÄ\x85ce domeny nie majÄ\x85 poprawnie skonfigurowanych mechanizmÃ³w weryfikacji nadawcy wiadomoÅ\x9bci e-mail:        <ul>",
                            "                    <li>",
                            "                        test-smtp-server.artemis:",
                            "",
                            "                            Nie znaleziono poprawnego rekordu DMARC. Rekomendujemy uÅ¼ywanie wszystkich trzech mechanizmÃ³w: SPF, DKIM i DMARC, aby zmniejszyÄ\x87 szansÄ\x99, Å¼e sfaÅ\x82szowana wiadomoÅ\x9bÄ\x87 zostanie zaakceptowana przez serwer odbiorcy.",
                            "                        ",
                            "                    </li>",
                            "        </ul>",
                            "        <p>",
                            "            WdroÅ¼enie tych mechanizmÃ³w znaczÄ\x85co zwiÄ\x99kszy szansÄ\x99, Å¼e serwer odbiorcy odrzuci sfaÅ\x82szowanÄ\x85 wiadomoÅ\x9bÄ\x87 e-mail z powyÅ¼szych domen. W serwisie <a href='https://bezpiecznapoczta.cert.pl'>https://bezpiecznapoczta.cert.pl</a> moÅ¼na zweryfikowaÄ\x87 poprawnoÅ\x9bÄ\x87 implementacji mechanizmÃ³w weryfikacji nadawcy poczty w PaÅ\x84stwa domenie.<br/><br/>WiÄ\x99cej informacji o dziaÅ\x82aniu mechanizmÃ³w weryfikacji nadawcy moÅ¼na znaleÅºÄ\x87 pod adresem <a href='https://cert.pl/posts/2021/10/mechanizmy-weryfikacji-nadawcy-wiadomosci'>https://cert.pl/posts/2021/10/mechanizmy-weryfikacji-nadawcy-wiadomosci</a>.",
                            "            Nawet w przypadku domeny niesÅ\x82uÅ¼Ä\x85cej do wysyÅ\x82ki poczty rekordy SPF i DMARC sÄ\x85 potrzebne w celu ograniczenia moÅ¼liwoÅ\x9bci podszycia siÄ\x99 pod niÄ\x85. Odpowiednia konfiguracja jest opisana w powyÅ¼szym artykule.",
                            "        </p>",
                            "    </li>",
                            "        </ol>",
                            "    </body>",
                            "</html>",
                        ]
                    ),
                )
