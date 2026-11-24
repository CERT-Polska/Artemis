"""The cost of shortening a PoC URL, measured with the real Nuclei binary and
the real open-redirect-bypass template against a local target that counts
the requests it gets.

open-redirect-bypass has ~106 payloads and stops at the first match. A
re-fuzz of a subset without the vulnerable parameter used to go through all of
them - ~106 requests, at -rate-limit 1 longer than the re-fuzz timeout - so
every such finding timed out and kept its full PoC URL.
"""

import http.server
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.parse
from typing import Any, Dict, List
from unittest.mock import patch

from artemis.crawling import add_injectable_params_and_common_params_from_wordlist
from artemis.modules.nuclei import (
    DAST_SCANNING,
    NUCLEI_TEMPLATES_LOCATION,
    _InBandReproducer,
    _minimize_dast_finding,
    build_common_nuclei_command,
)

TEMPLATE = os.path.join(NUCLEI_TEMPLATES_LOCATION, "dast/vulnerabilities/redirect/open-redirect-bypass.yaml")


class _Target(http.server.BaseHTTPRequestHandler):
    """An open redirect in `next`; every request is recorded."""

    protocol_version = "HTTP/1.1"
    requests: List[str] = []
    lock = threading.Lock()

    def do_GET(self) -> None:
        with self.lock:
            self.requests.append(self.path)
        params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(self.path).query, keep_blank_values=True))
        if "next" in params:
            self.send_response(302)
            self.send_header("Location", params["next"].encode("latin-1", errors="replace").decode("latin-1"))
        else:
            self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args: Any) -> None:
        pass


@unittest.skipUnless(shutil.which("nuclei") and os.path.exists(TEMPLATE), "needs nuclei and its templates")
class TestPocRefuzzCost(unittest.TestCase):
    server: http.server.ThreadingHTTPServer
    finding: Dict[str, Any]

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Target)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

        # The DAST target the scan builds from a link.
        url = f"http://127.0.0.1:{cls.server.server_port}/go"
        with patch("artemis.crawling.get_injectable_parameters", return_value=[]):
            for data in DAST_SCANNING.values():
                url = add_injectable_params_and_common_params_from_wordlist(
                    url, data["params_wordlist"], data["param_default_value"]
                )

        # The finding, as the scan reports it.
        output = subprocess.run(
            build_common_nuclei_command()
            + ["-u", url, "-t", TEMPLATE, "-dast", "-fuzzing-mode", "multiple", "-silent", "-ni"],
            capture_output=True,
            # Nuclei waits 3 minutes for targets on an open stdin pipe.
            stdin=subprocess.DEVNULL,
            timeout=300,
            check=True,
        ).stdout.decode()
        findings = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
        assert len(findings) == 1, output
        cls.finding = findings[0]
        assert urllib.parse.urlparse(cls.finding["url"]).query.count("&") > 100

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()

    def _requests_for(self, function: Any, *args: Any) -> Any:
        with _Target.lock:
            _Target.requests.clear()
        result = function(*args)
        with _Target.lock:
            return result, len(_Target.requests)

    def test_a_check_costs_a_request_or_two_either_way(self) -> None:
        base = self.finding["url"]
        without_next = base.replace("&next=", "&other=")
        with tempfile.TemporaryDirectory() as workdir:
            reproducer = _InBandReproducer(TEMPLATE, "open-redirect-bypass", self.finding, workdir)
            self.assertTrue(reproducer.describe().startswith("narrowing=narrowed payloads="), reproducer.describe())

            reproduced, requests = self._requests_for(reproducer, base)
            self.assertTrue(reproduced)
            self.assertLessEqual(requests, 3)

            # The case that used to time out: no vulnerable parameter left.
            reproduced, requests = self._requests_for(reproducer, without_next)
            self.assertFalse(reproduced)
            self.assertLessEqual(requests, 3)

            reproduced, requests = self._requests_for(
                reproducer, urllib.parse.urlparse(base)._replace(query="next=x").geturl()
            )
            self.assertTrue(reproduced)
            self.assertLessEqual(requests, 3)

    def test_whole_minimization(self) -> None:
        result, requests = self._requests_for(_minimize_dast_finding, dict(self.finding))
        self.assertEqual(urllib.parse.urlparse(result).query, "next=//oast.me")
        # The payload comes from matched-at, byte-for-byte.
        self.assertIn("next=//oast.me", self.finding["matched-at"].split("&"))
        # ~10 re-fuzzes of a request or two each - a single miss with the
        # whole template would cost ~106.
        self.assertLessEqual(requests, 40)


if __name__ == "__main__":
    unittest.main()
