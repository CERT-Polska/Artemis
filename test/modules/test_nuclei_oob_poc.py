"""Shortening the PoC URL of an out-of-band finding, with the real Nuclei
binary, the real blind-oast-polyglots template and the interactsh server of
the test environment: a local target calls back to the OAST URL it gets in
`cmd`, the way a blind command injection would.
"""

import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import unittest
import urllib.parse
from typing import Any, Dict, Optional
from unittest.mock import patch

from artemis.config import Config
from artemis.crawling import add_injectable_params_and_common_params_from_wordlist
from artemis.modules.nuclei import (
    DAST_SCANNING,
    NUCLEI_TEMPLATES_LOCATION,
    _minimize_dast_finding,
    build_common_nuclei_command,
)

TEMPLATE = os.path.join(NUCLEI_TEMPLATES_LOCATION, "dast/vulnerabilities/cmdi/blind-oast-polyglots.yaml")
# <unique id>.<interactsh domain, or host:port of a local server>
OAST_HOST = re.compile(r"([a-z0-9]{33})\.([a-z0-9.\-]+(?::[0-9]+)?)")


def _call_back(oast_id: str, domain: str) -> None:
    host, _, port = domain.partition(":")
    # The OAST host itself, as a vulnerable server would - or, for a local
    # interactsh server addressed by IP, that server with the OAST Host header.
    for address in (f"{oast_id}.{host}", host):
        try:
            with socket.create_connection((address, int(port or 80)), timeout=10) as connection:
                connection.sendall(f"GET / HTTP/1.1\r\nHost: {oast_id}.{domain}\r\nConnection: close\r\n\r\n".encode())
                connection.recv(100)
            return
        except OSError:
            continue


class _BlindCommandInjection(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    calling_back = True

    def do_GET(self) -> None:
        params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(self.path).query, keep_blank_values=True))
        if self.calling_back:
            for oast_id, domain in set(OAST_HOST.findall(params.get("cmd", "").lower())):
                threading.Thread(target=_call_back, args=(oast_id, domain), daemon=True).start()
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args: Any) -> None:
        pass


@unittest.skipUnless(
    shutil.which("nuclei") and os.path.exists(TEMPLATE) and Config.Modules.Nuclei.NUCLEI_INTERACTSH_SERVER,
    "needs nuclei, its templates and an interactsh server",
)
@patch("artemis.config.Config.Modules.Nuclei.NUCLEI_REFUZZ_OOB_INTERACTIONS_COOLDOWN_SECONDS", 15)
class TestOobPocShortened(unittest.TestCase):
    server: http.server.ThreadingHTTPServer
    finding: Optional[Dict[str, Any]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _BlindCommandInjection)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{cls.server.server_port}/run"
        with patch("artemis.crawling.get_injectable_parameters", return_value=[]):
            for data in DAST_SCANNING.values():
                url = add_injectable_params_and_common_params_from_wordlist(
                    url, data["params_wordlist"], data["param_default_value"]
                )
        output = subprocess.run(
            build_common_nuclei_command()
            + ["-u", url, "-t", TEMPLATE, "-dast", "-fuzzing-mode", "multiple", "-silent"],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=300,
        ).stdout.decode()
        findings = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
        cls.finding = findings[0] if findings else None

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()

    def setUp(self) -> None:
        if self.finding is None:
            self.skipTest("the scan got no callback from the interactsh server")
        _BlindCommandInjection.calling_back = True

    def test_shortened_to_the_parameter_that_calls_back(self) -> None:
        assert self.finding is not None
        self.assertTrue(self.finding.get("interaction"))
        finding = dict(self.finding)
        result = _minimize_dast_finding(finding)
        self.assertEqual(list(urllib.parse.parse_qs(urllib.parse.urlparse(result).query)), ["cmd"])
        self.assertEqual(
            (finding["poc_minimization"]["outcome"], finding["poc_minimization"]["oob"]), ("shortened", True)
        )
        # The payload is the one of the scan, byte-for-byte.
        self.assertIn(urllib.parse.urlparse(result).query, self.finding["matched-at"].split("&"))

    def test_full_url_kept_when_the_target_does_not_call_back_again(self) -> None:
        assert self.finding is not None
        _BlindCommandInjection.calling_back = False
        finding = dict(self.finding)
        self.assertEqual(_minimize_dast_finding(finding), self.finding["matched-at"])
        self.assertEqual(finding["poc_minimization"]["outcome"], "fallback_no_reproduce")


class _CmdExeCommandInjection(http.server.BaseHTTPRequestHandler):
    """Runs what follows `cmd` in the raw query up to the next parameter, the
    way cmd.exe runs "&"-separated commands: only a payload with a raw "&"
    calls back. Nuclei moves the segments that are the same in every
    parameter behind the first one, so `cmd` comes first."""

    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        segments = urllib.parse.urlparse(self.path).query.split("&")
        if segments and segments[0].startswith("cmd="):
            command = []
            for segment in segments[1:]:
                if "=" in segment:
                    break
                command.append(urllib.parse.unquote_plus(segment))
            for oast_id, domain in set(OAST_HOST.findall(" ".join(command).lower())):
                threading.Thread(target=_call_back, args=(oast_id, domain), daemon=True).start()
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args: Any) -> None:
        pass


@unittest.skipUnless(
    shutil.which("nuclei") and os.path.exists(TEMPLATE) and Config.Modules.Nuclei.NUCLEI_INTERACTSH_SERVER,
    "needs nuclei, its templates and an interactsh server",
)
@patch("artemis.config.Config.Modules.Nuclei.NUCLEI_REFUZZ_OOB_INTERACTIONS_COOLDOWN_SECONDS", 15)
class TestOobPocWithARawAmpersand(unittest.TestCase):
    """blind-oast-polyglots' cmd.exe payload, "&nslookup ...&'...": the
    canary keeps it, and the callback is attributed by the OAST URL, which
    stays behind its parameter."""

    server: http.server.ThreadingHTTPServer
    finding: Optional[Dict[str, Any]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CmdExeCommandInjection)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{cls.server.server_port}/run?cmd=testing"
        with patch("artemis.crawling.get_injectable_parameters", return_value=[]):
            for data in DAST_SCANNING.values():
                url = add_injectable_params_and_common_params_from_wordlist(
                    url, data["params_wordlist"], data["param_default_value"]
                )
        output = subprocess.run(
            build_common_nuclei_command()
            + ["-u", url, "-t", TEMPLATE, "-dast", "-fuzzing-mode", "multiple", "-silent"],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=300,
        ).stdout.decode()
        findings = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
        cls.finding = findings[0] if findings else None

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()

    def test_shortened_to_cmd(self) -> None:
        if self.finding is None:
            self.skipTest("the scan got no callback from the interactsh server")
        self.assertTrue(self.finding.get("interaction"))
        finding = dict(self.finding)
        result = _minimize_dast_finding(finding)
        query = urllib.parse.urlparse(result).query
        segments = query.split("&")
        # cmd, followed by the segments of the payload.
        self.assertTrue(segments[0].startswith("cmd="), result)
        self.assertTrue(all("=" not in segment for segment in segments[1:]), result)
        self.assertTrue(any("nslookup" in segment for segment in segments[1:]), result)
        # Cut out of the scan's matched-at byte-for-byte.
        self.assertIn(query, self.finding["matched-at"])
        self.assertEqual(
            (finding["poc_minimization"]["outcome"], finding["poc_minimization"]["params_after"]), ("shortened", 1)
        )


if __name__ == "__main__":
    unittest.main()
