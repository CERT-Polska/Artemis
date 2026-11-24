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

OOB_TEMPLATE = """
id: blind-ssrf
info:
  name: Blind SSRF
  severity: medium
http:
  - payloads:
      ssrf:
        - "{{interactsh-url}}"
    fuzzing:
      - part: query
        fuzz:
          - "https://{{ssrf}}"
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
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
        self.directory = tempfile.mkdtemp()
        self.template_path = os.path.join(self.directory, "open-redirect-bypass.yaml")
        with open(self.template_path, "w") as f:
            f.write(TEMPLATE)
        self.finding: Dict[str, Any] = {"template-id": "open-redirect-bypass", "url": BASE, "matched-at": MATCHED}

    def tearDown(self) -> None:
        for name in os.listdir(self.directory):
            os.unlink(os.path.join(self.directory, name))
        os.rmdir(self.directory)

    def test_narrowed_to_the_payload_that_hit(self) -> None:
        fake = _FakeNuclei()
        with tempfile.TemporaryDirectory() as workdir, patch("artemis.modules.nuclei.subprocess.run", fake):
            reproducer = _InBandReproducer(self.template_path, "open-redirect-bypass", self.finding, workdir)
            self.assertEqual(reproducer.describe(), "narrowing=narrowed payloads=1/4")
            self.assertTrue(reproducer(BASE))
            self.assertFalse(reproducer(BASE.replace("next=", "other=")))
            # Both checks used the narrowed copy, without interactsh.
            self.assertTrue(all(path != self.template_path for path in fake.templates()))
            self.assertTrue(all("-ni" in command for command in fake.commands))

    def test_misidentified_payload_is_found_by_bisection(self) -> None:
        """If the narrowed template misses on the full URL - which the scan
        has just reported - a payload that fires is looked for by bisecting
        the list on that URL, and used from then on."""
        self.finding["matched-at"] = BASE.replace("next=http%3A%2F%2F127.0.0.1%2Fabc.html", "next=oast.me")
        fake = _FakeNuclei()
        with tempfile.TemporaryDirectory() as workdir, patch("artemis.modules.nuclei.subprocess.run", fake):
            reproducer = _InBandReproducer(self.template_path, "open-redirect-bypass", self.finding, workdir)
            self.assertTrue(reproducer(BASE))
            self.assertEqual(reproducer.describe(), "narrowing=bisected payloads=1/4")
            # narrowed (miss), the first half (hit), its first half (miss),
            # then the last candidate, which no check has confirmed yet.
            self.assertEqual(
                [os.path.basename(path) for path in fake.templates()],
                ["narrowed.yaml", "bisect2.yaml", "bisect1.yaml", "bisected.yaml"],
            )
            self.assertFalse(reproducer(BASE.replace("next=", "other=")))
            self.assertEqual(os.path.basename(fake.templates()[-1]), "bisected.yaml")
            self.assertIn("//oast.me", fake.texts[-1])
            self.assertNotIn("{{Hostname}}", fake.texts[-1])

    def test_bisected_without_the_fuzzed_url(self) -> None:
        del self.finding["url"]
        fake = _FakeNuclei()
        with tempfile.TemporaryDirectory() as workdir, patch("artemis.modules.nuclei.subprocess.run", fake):
            reproducer = _InBandReproducer(self.template_path, "open-redirect-bypass", self.finding, workdir)
            self.assertEqual(reproducer.describe(), "narrowing=url_not_aligned payloads=all")
            self.assertTrue(reproducer(MATCHED))
            self.assertEqual(reproducer.describe(), "narrowing=bisected payloads=1/4")
            self.assertNotIn(self.template_path, fake.templates())

    def test_bisection_cost(self) -> None:
        """A payload list of 64, the one that fires at the end: ~6 re-fuzzes
        once, then every check costs one request."""
        entries = [f"'/x{i}'" for i in range(63)] + ['"//oast.me"']
        with open(self.template_path, "w") as f:
            f.write(
                TEMPLATE.replace('        - "{{Hostname}}.oast.me"\n', "".join(f"        - {e}\n" for e in entries))
            )
        self.finding["matched-at"] = BASE.replace("next=http%3A%2F%2F127.0.0.1%2Fabc.html", "next=unknown")
        fake = _FakeNuclei()
        with tempfile.TemporaryDirectory() as workdir, patch("artemis.modules.nuclei.subprocess.run", fake):
            reproducer = _InBandReproducer(self.template_path, "open-redirect-bypass", self.finding, workdir)
            self.assertTrue(reproducer(BASE))
            self.assertLessEqual(len(fake.commands), 8)
            self.assertEqual(reproducer.describe(), "narrowing=bisected payloads=1/67")
            before = len(fake.commands)
            self.assertFalse(reproducer(BASE.replace("next=", "other=")))
            self.assertEqual(len(fake.commands), before + 1)

    def test_interactsh_kept_for_templates_that_send_oast_urls(self) -> None:
        with open(self.template_path, "w") as f:
            f.write(TEMPLATE.replace('"oast.me"', '"http://{{interactsh-url}}"'))
        self.finding["matched-at"] = BASE.replace("next=http%3A%2F%2F127.0.0.1%2Fabc.html", "next=http://ab12.oast.fun")
        fake = _FakeNuclei()
        with tempfile.TemporaryDirectory() as workdir, patch("artemis.modules.nuclei.subprocess.run", fake):
            reproducer = _InBandReproducer(self.template_path, "open-redirect-bypass", self.finding, workdir)
            reproducer(BASE)
        self.assertIn("{{interactsh-url}}", fake.texts[0])
        for command, text in zip(fake.commands, fake.texts):
            self.assertEqual("-ni" in command, "{{interactsh-url}}" not in text)

    def test_hit_before_a_timeout_counts(self) -> None:
        with (
            tempfile.TemporaryDirectory() as workdir,
            patch(
                "artemis.modules.nuclei.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="nuclei", timeout=1, output=HIT, stderr=_trace("none")),
            ),
        ):
            reproducer = _InBandReproducer(self.template_path, "open-redirect-bypass", self.finding, workdir)
            with self.assertLogs("artemis.poc_minimization", level="INFO") as logs:
                self.assertTrue(reproducer(BASE))
        self.assertRegex(logs.output[0], r"reproduced=yes .* error=timeout$")

    def test_error_logged_then_raised(self) -> None:
        with (
            tempfile.TemporaryDirectory() as workdir,
            patch(
                "artemis.modules.nuclei.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="nuclei", timeout=1, stderr=_trace("none")),
            ),
        ):
            reproducer = _InBandReproducer(self.template_path, "open-redirect-bypass", self.finding, workdir)
            with self.assertLogs("artemis.poc_minimization", level="INFO") as logs:
                with self.assertRaisesRegex(RefuzzError, "timeout"):
                    reproducer(BASE)
        (line,) = logs.output
        self.assertRegex(
            line,
            r"PoC minimization re-fuzz: template=open-redirect-bypass call=1 params=61 payloads=1/4 "
            r"reproduced=error elapsed=\d+\.\ds requests=1 request_errors=none error=timeout$",
        )
        self.assertNotIn("example.com", line)
        self.assertNotIn("oast", line)

    @patch.dict("artemis.modules.nuclei._minimization_attempts", clear=True)
    def test_outcome_stored_with_the_finding(self) -> None:
        findings = [dict(self.finding, **{"template-path": self.template_path}) for _ in range(2)]
        with patch("artemis.modules.nuclei.subprocess.run", _FakeNuclei()):
            for finding in findings:
                _minimize_dast_finding(finding)
        stored = findings[0]["poc_minimization"]
        self.assertEqual(stored["outcome"], "shortened")
        self.assertEqual((stored["params_before"], stored["params_after"]), (61, 1))
        self.assertEqual((stored["narrowing"], stored["payloads"], stored["oob"]), ("narrowed", "1/4", False))
        self.assertEqual(stored["attempt"], 1)
        self.assertNotIn("example.com", json.dumps(stored))
        self.assertNotIn("oast", json.dumps(stored))
        # The same finding again, as when module_base re-runs a failed batch.
        self.assertEqual(findings[1]["poc_minimization"]["attempt"], 2)

    def test_whole_minimization_cost(self) -> None:
        fake = _FakeNuclei()
        with patch("artemis.modules.nuclei.subprocess.run", fake):
            with self.assertLogs("artemis.poc_minimization", level="INFO") as logs:
                result = _minimize_dast_finding(dict(self.finding, **{"template-path": self.template_path}))
        self.assertEqual(result, "http://example.com/go?next=//oast.me")
        self.assertRegex(logs.output[-1], r"outcome=shortened .* base=url .* narrowing=narrowed payloads=1/4$")
        # Every call cost one request: with the whole template a miss would cost four.
        self.assertTrue(all(line.endswith("requests=1 request_errors=none") for line in logs.output[:-1]))


OOB_NAMES = [f"p{i}" for i in range(30)] + ["next"] + [f"q{i}" for i in range(30)]
OOB_BASE = "http://example.com/go?" + "&".join(f"{name}=http%3A%2F%2F127.0.0.1%2Fabc.html" for name in OOB_NAMES)
OOB_MATCHED = OOB_BASE.replace(
    "http%3A%2F%2F127.0.0.1%2Fabc.html", "https://d4f8a2c1b0e9d4f8a2c1b0e9d4f8a2c1b.oast.fun"
)


class _FakeOobNuclei:
    """Stands in for subprocess.run with an OOB template: puts a distinct
    OAST URL into every parameter (as the canary makes Nuclei do) and reports
    a callback for the one in `next`."""

    def __init__(self, callback: bool = True, timeout: bool = False) -> None:
        self.callback = callback
        self.timeout = timeout
        self.commands: List[List[str]] = []
        self.templates: List[str] = []
        self.timeouts: List[int] = []

    def __call__(self, command: List[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        self.commands.append(command)
        self.timeouts.append(kwargs["timeout"])
        with open(command[command.index("-t") + 1]) as f:
            self.templates.append(f.read())
        url = command[command.index("-u") + 1]
        base, query = url.split("?", 1)
        tokens = {}
        pairs = []
        for i, pair in enumerate(query.split("&")):
            name = pair.split("=", 1)[0]
            tokens[name] = f"{i:033d}"
            pairs.append(f"{name}=https://{tokens[name]}.oast.fun")
        sent = base + "?" + "&".join(pairs)
        results = b""
        if self.callback and "next" in tokens:
            results = (
                json.dumps(
                    # Nuclei may report the interaction against another request.
                    {
                        "template-id": "blind-ssrf",
                        "matched-at": "elsewhere",
                        "interaction": {"unique-id": tokens["next"]},
                    }
                ).encode()
                + b"\n"
            )
        trace = json.dumps(
            {"template": "t", "type": "http", "input": sent, "address": "a:80", "error": "none"}
        ).encode()
        if self.timeout:
            raise subprocess.TimeoutExpired(cmd=command, timeout=1, output=results, stderr=trace + b"\n")
        return _completed(results, trace + b"\n")


class TestOobFindings(unittest.TestCase):
    def setUp(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(OOB_TEMPLATE)
        self.addCleanup(os.unlink, f.name)
        self.finding = {
            "template-id": "blind-ssrf",
            "template-path": f.name,
            "url": OOB_BASE,
            "matched-at": OOB_MATCHED,
            "interaction": {"protocol": "http", "unique-id": "d4f8a2c1b0e9d4f8a2c1b0e9d4f8a2c1b"},
        }

    def test_shortened_by_the_parameter_that_called_back(self) -> None:
        fake = _FakeOobNuclei()
        with patch("artemis.modules.nuclei.subprocess.run", fake):
            with self.assertLogs("artemis.poc_minimization", level="INFO") as logs:
                result = _minimize_dast_finding(self.finding)
        self.assertEqual(result, "http://example.com/go?next=https://d4f8a2c1b0e9d4f8a2c1b0e9d4f8a2c1b.oast.fun")
        # One re-fuzz of the whole URL, one of the shortened one.
        self.assertEqual(len(fake.commands), 2)
        self.assertEqual(
            fake.commands[1][fake.commands[1].index("-u") + 1],
            "http://example.com/go?next=http%3A%2F%2F127.0.0.1%2Fabc.html",
        )
        for command, template in zip(fake.commands, fake.templates):
            self.assertNotIn("-ni", command)
            self.assertEqual(command[command.index("-fuzzing-mode") + 1], "multiple")
            self.assertEqual(
                command[command.index("-interactions-cooldown-period") + 1],
                str(Config.Modules.Nuclei.NUCLEI_REFUZZ_OOB_INTERACTIONS_COOLDOWN_SECONDS),
            )
            # The canary: the payload sits in the fuzz expression.
            self.assertNotIn("payloads", template)
            self.assertIn("https://{{interactsh-url}}", template)
        self.assertEqual(fake.timeouts, [Config.Modules.Nuclei.NUCLEI_REFUZZ_OOB_TIMEOUT_SECONDS] * 2)
        self.assertRegex(logs.output[-1], r"params=61->1 outcome=shortened oob=1 .* refuzz=canary payloads=1$")

    def test_callback_before_a_timeout_counts(self) -> None:
        with patch("artemis.modules.nuclei.subprocess.run", _FakeOobNuclei(timeout=True)):
            result = _minimize_dast_finding(self.finding)
        self.assertEqual(result, "http://example.com/go?next=https://d4f8a2c1b0e9d4f8a2c1b0e9d4f8a2c1b.oast.fun")

    def test_no_callback_keeps_the_full_url(self) -> None:
        with patch("artemis.modules.nuclei.subprocess.run", _FakeOobNuclei(callback=False)):
            self.assertEqual(_minimize_dast_finding(self.finding), OOB_MATCHED)


class TestOobRouting(unittest.TestCase):
    def test_template_with_both_kinds_of_matchers(self) -> None:
        """A finding of a template that also matches the response
        (generic-xxe, jinjava-oob) without an interaction is in-band."""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(OOB_TEMPLATE)
        self.addCleanup(os.unlink, f.name)
        finding = {"template-id": "blind-ssrf", "template-path": f.name, "url": BASE, "matched-at": MATCHED}
        with patch("artemis.modules.nuclei.subprocess.run", return_value=_completed()) as run:
            with self.assertLogs("artemis.poc_minimization", level="INFO") as logs:
                _minimize_dast_finding(finding)
        run.assert_called()
        self.assertNotIn("oob=1", logs.output[-1])

    def test_oob_template_without_a_canary(self) -> None:
        """The full URL is kept only when no canary can be made - and the
        summary line says why."""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(OOB_TEMPLATE.replace('"https://{{ssrf}}"', '"{{url_encode(ssrf)}}"'))
        self.addCleanup(os.unlink, f.name)
        finding = {
            "template-id": "blind-ssrf",
            "template-path": f.name,
            "url": OOB_BASE,
            "matched-at": OOB_MATCHED,
            "interaction": {"unique-id": "d4f8a2c1b0e9d4f8a2c1b0e9d4f8a2c1b"},
        }
        with patch("artemis.modules.nuclei.subprocess.run") as run:
            with self.assertLogs("artemis.poc_minimization", level="INFO") as logs:
                self.assertEqual(_minimize_dast_finding(finding), OOB_MATCHED)
        run.assert_not_called()
        self.assertRegex(logs.output[0], r"outcome=fallback_error .* error=canary_not_supported$")


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
        self.assertEqual(
            (finding["poc_minimization"]["outcome"], finding["poc_minimization"]["error"]),
            ("fallback_error", "unexpected_ValueError"),
        )

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
            with tempfile.TemporaryDirectory() as workdir:
                with tempfile.NamedTemporaryFile("w", suffix=".yaml", dir=workdir, delete=False) as f:
                    f.write(TEMPLATE)
                reproducer = _InBandReproducer(f.name, "t", {"matched-at": MATCHED}, workdir)
                reproducer(MATCHED)
        self.assertEqual(run.call_args.kwargs["timeout"], Config.Modules.Nuclei.NUCLEI_REFUZZ_TIMEOUT_SECONDS)


if __name__ == "__main__":
    unittest.main()
