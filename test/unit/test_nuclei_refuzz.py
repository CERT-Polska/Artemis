import json
import os
import subprocess
import tempfile
import unittest
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import timeout_decorator

from artemis.config import Config
from artemis.modules.nuclei import (
    NUCLEI_TEMPLATES_LOCATION,
    _InBandReproducer,
    _is_dast_finding,
    _minimize_dast_finding,
    _run_refuzz,
    build_common_nuclei_command,
)
from artemis.reporting.modules.nuclei.poc_url_utils import RefuzzError

HIT = b'{"template-id": "sqli-error-based", "matched-at": "http://example.com/?sortby=%27"}\n'


def _trace(*errors: str) -> bytes:
    """Nuclei's -trace-log output: one JSON line per request sent."""
    return "".join(
        json.dumps(
            {"template": "t.yaml", "type": "http", "input": "http://example.com/", "address": "a:80", "error": e}
        )
        + "\n"
        for e in errors
    ).encode()


def _completed(stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class TestRunRefuzz(unittest.TestCase):
    URL = "http://example.com/?search=%27%22%3E%3Cx%3E&sortby=%27"

    @patch("artemis.modules.nuclei.subprocess.run", return_value=_completed(HIT, _trace("none")))
    def test_command_and_timeout(self, run: MagicMock) -> None:
        result = _run_refuzz(self.URL, "template.yaml", ["-nc"], 150)
        self.assertEqual(len(result.results), 1)
        (call,) = run.call_args_list
        command = list(call.args[0])
        common = build_common_nuclei_command()
        self.assertEqual(command[: len(common)], common)
        self.assertEqual(command[command.index("-fuzzing-mode") + 1], "multiple")
        self.assertEqual(command[command.index("-trace-log") + 1], "/dev/stderr")
        self.assertIn("-dast", command)
        self.assertIn("-nc", command)
        self.assertEqual(call.kwargs["timeout"], 150)
        # Otherwise Nuclei waits up to 3 minutes for targets on an open stdin pipe.
        self.assertEqual(call.kwargs["stdin"], subprocess.DEVNULL)
        # The URL is sent with its payloads byte-for-byte.
        self.assertEqual(command[command.index("-u") + 1], self.URL)

    @patch(
        "artemis.modules.nuclei.subprocess.run",
        return_value=_completed(
            b"", _trace("none", "context deadline exceeded", "dial tcp: i/o timeout") + b"[WRN] x\n"
        ),
    )
    def test_requests_and_errors_counted(self, _run: MagicMock) -> None:
        result = _run_refuzz(self.URL, "template.yaml", [], 150)
        self.assertEqual(result.results, [])
        self.assertEqual(result.requests, 3)
        self.assertEqual(result.errors, {"context_deadline_exceeded": 1, "io_timeout": 1})
        self.assertEqual(result.error, "")

    @patch(
        "artemis.modules.nuclei.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="nuclei", timeout=1, output=b"", stderr=_trace("none", "none")),
    )
    def test_timeout_keeps_what_was_sent(self, _run: MagicMock) -> None:
        result = _run_refuzz(self.URL, "template.yaml", [], 150)
        self.assertEqual(result.error, "timeout")
        self.assertEqual(result.requests, 2)

    @patch("artemis.modules.nuclei.subprocess.run", return_value=_completed(returncode=2))
    def test_nuclei_failure(self, _run: MagicMock) -> None:
        self.assertEqual(_run_refuzz(self.URL, "template.yaml", [], 150).error, "exit_code_2")

    @patch("artemis.modules.nuclei.subprocess.run", side_effect=FileNotFoundError())
    def test_missing_binary(self, _run: MagicMock) -> None:
        self.assertEqual(_run_refuzz(self.URL, "template.yaml", [], 150).error, "nuclei_missing")


TEMPLATE = """
id: open-redirect-bypass
info:
  name: Open Redirect Bypass
  severity: medium
http:
  - payloads:
      redirect:
        - "{{Hostname}}.oast.me"
        - "//oast.me"
        - "////oast.me"
        - "oast.me"
    fuzzing:
      - part: query
        keys:
          - next
        fuzz:
          - "{{redirect}}"
    stop-at-first-match: true
    matchers:
      - type: regex
        part: header
        regex:
          - "Location: //oast\\\\.me"
"""

NAMES = [f"p{i}" for i in range(30)] + ["next"] + [f"q{i}" for i in range(30)]
BASE = "http://example.com/go?" + "&".join(f"{name}=http%3A%2F%2F127.0.0.1%2Fabc.html" for name in NAMES)
MATCHED = BASE.replace("next=http%3A%2F%2F127.0.0.1%2Fabc.html", "next=//oast.me")


class _FakeNuclei:
    """Stands in for subprocess.run: reports the finding when the URL has
    `next` and the template given can still send //oast.me."""

    def __init__(self) -> None:
        self.commands: List[List[str]] = []
        self.texts: List[str] = []

    def __call__(self, command: List[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        self.commands.append(command)
        url = command[command.index("-u") + 1]
        with open(command[command.index("-t") + 1]) as f:
            template = f.read()
        self.texts.append(template)
        hit = "next=" in url and "//oast.me" in template
        payloads = template.count("oast.me")
        return _completed(HIT if hit else b"", _trace(*(["none"] * (1 if hit else payloads))))

    def templates(self) -> List[str]:
        return [command[command.index("-t") + 1] for command in self.commands]


class TestInBandReproducer(unittest.TestCase):
    def setUp(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(TEMPLATE)
        self.addCleanup(os.unlink, f.name)
        self.template_path = f.name
        self.finding: Dict[str, Any] = {
            "template-id": "open-redirect-bypass",
            "template-path": f.name,
            "url": BASE,
            "matched-at": MATCHED,
        }

    def test_re_fuzzed_with_the_template(self) -> None:
        fake = _FakeNuclei()
        with patch("artemis.modules.nuclei.subprocess.run", fake):
            reproducer = _InBandReproducer(self.template_path, "open-redirect-bypass")
            self.assertTrue(reproducer(BASE))
            self.assertFalse(reproducer(BASE.replace("next=", "other=")))
        self.assertEqual(fake.templates(), [self.template_path] * 2)

    def test_hit_before_a_timeout_counts(self) -> None:
        with patch(
            "artemis.modules.nuclei.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="nuclei", timeout=1, output=HIT, stderr=_trace("none")),
        ):
            reproducer = _InBandReproducer(self.template_path, "open-redirect-bypass")
            with self.assertLogs("artemis.poc_minimization", level="INFO") as logs:
                self.assertTrue(reproducer(BASE))
        self.assertRegex(logs.output[0], r"reproduced=yes .* error=timeout$")

    def test_error_logged_then_raised(self) -> None:
        with patch(
            "artemis.modules.nuclei.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="nuclei", timeout=1, stderr=_trace("none")),
        ):
            reproducer = _InBandReproducer(self.template_path, "open-redirect-bypass")
            with self.assertLogs("artemis.poc_minimization", level="INFO") as logs:
                with self.assertRaisesRegex(RefuzzError, "timeout"):
                    reproducer(BASE)
        (line,) = logs.output
        self.assertRegex(
            line,
            r"PoC minimization re-fuzz: template=open-redirect-bypass call=1 params=61 payloads=all "
            r"reproduced=error elapsed=\d+\.\ds requests=1 request_errors=none error=timeout$",
        )
        self.assertNotIn("example.com", line)
        self.assertNotIn("oast", line)

    def test_whole_minimization(self) -> None:
        fake = _FakeNuclei()
        with patch("artemis.modules.nuclei.subprocess.run", fake):
            with self.assertLogs("artemis.poc_minimization", level="INFO") as logs:
                result = _minimize_dast_finding(dict(self.finding))
        self.assertEqual(result, "http://example.com/go?next=//oast.me")
        self.assertRegex(logs.output[-1], r"params=61->1 outcome=shortened .* base=url url_sha=[0-9a-f]{12}$")
        # Subsets are re-fuzzed from the URL Nuclei fuzzed, with the original values.
        for command in fake.commands:
            self.assertNotIn("//oast.me", command[command.index("-u") + 1])
        # A miss goes through the whole payload list: four requests here.
        self.assertTrue(
            any("reproduced=no" in line and line.endswith("requests=4 request_errors=none") for line in logs.output)
        )


class TestIsDastFinding(unittest.TestCase):
    PRODUCTION_PATH = "/root/nuclei-templates/dast/vulnerabilities/sqli/sqli-error-based.yaml"

    def test_production_template_path(self) -> None:
        """The path Nuclei reports in production must enable minimization -
        otherwise it would silently never run."""
        self.assertTrue(_is_dast_finding({"template-path": self.PRODUCTION_PATH}))

    def test_path_built_the_way_the_scan_builds_it(self) -> None:
        # The scan passes NUCLEI_TEMPLATES_LOCATION + "dast/...", with whatever
        # slashes NUCLEI_TEMPLATES_LOCATION has.
        template = "dast/vulnerabilities/xss/reflected-xss.yaml"
        self.assertTrue(_is_dast_finding({"template-path": NUCLEI_TEMPLATES_LOCATION + template}))
        self.assertTrue(_is_dast_finding({"template-path": NUCLEI_TEMPLATES_LOCATION.rstrip("/") + "//" + template}))

    def test_relative_template_field(self) -> None:
        self.assertTrue(_is_dast_finding({"template": "dast/vulnerabilities/sqli/sqli-error-based.yaml"}))

    def test_non_dast_templates(self) -> None:
        for template in (
            "http/vulnerabilities/generic/xss-fuzz.yaml",
            "http/cves/2020/CVE-2020-28976.yaml",
            "http/vulnerabilities/dast/not-really.yaml",
        ):
            self.assertFalse(
                _is_dast_finding({"template": template, "template-path": NUCLEI_TEMPLATES_LOCATION + template})
            )
        self.assertFalse(_is_dast_finding({"template-id": "something"}))


class TestUnexpectedErrors(unittest.TestCase):
    def test_finding_kept(self) -> None:
        """A bug in the minimization must not lose the finding, nor fail the
        batch: the PoC stays as it was."""
        finding: Dict[str, Any] = {
            "template-id": "open-redirect-bypass",
            "template-path": "/nonexistent/open-redirect-bypass.yaml",
            "url": BASE,
            "matched-at": MATCHED,
        }
        with patch(
            "artemis.modules.nuclei.minimize_nuclei_matched_at_url", side_effect=ValueError("http://example.com/secret")
        ):
            with self.assertLogs("artemis.poc_minimization", level="INFO") as logs:
                self.assertEqual(_minimize_dast_finding(finding), MATCHED)
        self.assertRegex(logs.output[0], r"PoC minimization failed: ValueError at nuclei\.py:\d+$")
        self.assertRegex(logs.output[1], r"outcome=fallback_error .* error=unexpected_ValueError$")
        self.assertNotIn("example.com", "".join(logs.output))

    def test_task_timeout_not_swallowed(self) -> None:
        """module_base ends a batch past TASK_TIMEOUT_SECONDS with
        timeout_decorator's TimeoutError, which is an Exception as well: it
        must reach module_base, not be taken for a minimization bug."""
        finding: Dict[str, Any] = {
            "template-id": "open-redirect-bypass",
            "template-path": "/nonexistent/open-redirect-bypass.yaml",
            "url": BASE,
            "matched-at": MATCHED,
        }
        with patch(
            "artemis.modules.nuclei.minimize_nuclei_matched_at_url",
            side_effect=timeout_decorator.TimeoutError("Timed Out"),
        ):
            with self.assertRaises(timeout_decorator.TimeoutError):
                _minimize_dast_finding(finding)


class TestRefuzzConfig(unittest.TestCase):
    def test_timeout_used(self) -> None:
        with patch("artemis.modules.nuclei.subprocess.run", return_value=_completed()) as run:
            _InBandReproducer("template.yaml", "t")(MATCHED)
        self.assertEqual(run.call_args.kwargs["timeout"], Config.Modules.Nuclei.NUCLEI_REFUZZ_TIMEOUT_SECONDS)


if __name__ == "__main__":
    unittest.main()
