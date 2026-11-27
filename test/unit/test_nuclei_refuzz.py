import os
import subprocess
import tempfile
import unittest
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import timeout_decorator
import yaml

from artemis.config import Config
from artemis.modules.nuclei import (
    NARROW_ABOVE_PAYLOADS,
    NUCLEI_TEMPLATES_LOCATION,
    _is_dast_finding,
    _minimize_dast_finding,
    _Reproducer,
    _reproduces_with_nuclei,
    build_common_nuclei_command,
)
from artemis.reporting.modules.nuclei.poc_url_utils import RefuzzError

HIT = b'{"template-id": "sqli-error-based", "fuzzing_parameter": "sortby"}\n'


class TestReproducesWithNuclei(unittest.TestCase):
    URL = "http://example.com/?search=%27%22%3E%3Cx%3E&sortby=%27"

    @patch("artemis.modules.nuclei.subprocess.check_output", return_value=HIT)
    def test_command_and_timeout(self, check_output: MagicMock) -> None:
        self.assertTrue(_reproduces_with_nuclei(self.URL, "template.yaml"))
        (call,) = check_output.call_args_list
        command = list(call.args[0])
        common = build_common_nuclei_command()
        self.assertEqual(command[: len(common)], common)
        self.assertEqual(command[command.index("-fuzzing-mode") + 1], "multiple")
        self.assertIn("-dast", command)
        self.assertEqual(call.kwargs["timeout"], Config.Modules.Nuclei.NUCLEI_REFUZZ_TIMEOUT_SECONDS)
        # The URL is sent with its matched-at payloads byte-for-byte.
        self.assertEqual(command[command.index("-u") + 1], self.URL)

    @patch("artemis.modules.nuclei.subprocess.check_output", return_value=b"")
    def test_no_hit(self, _check_output: MagicMock) -> None:
        self.assertFalse(_reproduces_with_nuclei(self.URL, "template.yaml"))

    @patch(
        "artemis.modules.nuclei.subprocess.check_output",
        side_effect=subprocess.TimeoutExpired(cmd="nuclei", timeout=1),
    )
    def test_timeout_is_an_error_not_a_miss(self, _check_output: MagicMock) -> None:
        with self.assertRaisesRegex(RefuzzError, "timeout"):
            _reproduces_with_nuclei(self.URL, "template.yaml")

    @patch(
        "artemis.modules.nuclei.subprocess.check_output",
        side_effect=subprocess.CalledProcessError(returncode=2, cmd="nuclei"),
    )
    def test_nuclei_failure_is_an_error_not_a_miss(self, _check_output: MagicMock) -> None:
        with self.assertRaisesRegex(RefuzzError, "exit_code_2"):
            _reproduces_with_nuclei(self.URL, "template.yaml")

    @patch("artemis.modules.nuclei.subprocess.check_output", side_effect=FileNotFoundError())
    def test_missing_binary_is_an_error_not_a_miss(self, _check_output: MagicMock) -> None:
        with self.assertRaisesRegex(RefuzzError, "nuclei_missing"):
            _reproduces_with_nuclei(self.URL, "template.yaml")

    @patch("artemis.modules.nuclei.subprocess.check_output", return_value=b"")
    def test_stdin_closed(self, check_output: MagicMock) -> None:
        """Nuclei reads targets from stdin when it is a pipe - and waits up to
        3 minutes for them, longer than the re-fuzz timeout."""
        _reproduces_with_nuclei(self.URL, "template.yaml")
        self.assertIs(check_output.call_args.kwargs["stdin"], subprocess.DEVNULL)

    @patch(
        "artemis.modules.nuclei.subprocess.check_output",
        side_effect=subprocess.TimeoutExpired(cmd="nuclei", timeout=1, output=HIT),
    )
    def test_hit_before_a_timeout_counts(self, _check_output: MagicMock) -> None:
        self.assertTrue(_reproduces_with_nuclei(self.URL, "template.yaml"))


# open-redirect-bypass in short: a long payload list, of which "//oast.me" fires.
PAYLOADS = ["yes"] + [f"/x{i}" for i in range(NARROW_ABOVE_PAYLOADS + 10)] + ["//oast.me"]
TEMPLATE: Dict[str, Any] = {
    "id": "open-redirect-bypass",
    "info": {"name": "Open Redirect Bypass", "severity": "medium"},
    "http": [
        {
            "payloads": {"redirect": PAYLOADS},
            "fuzzing": [{"part": "query", "keys": ["next"], "fuzz": ["{{redirect}}"]}],
            "stop-at-first-match": True,
            "matchers": [{"type": "status", "status": [302]}],
        }
    ],
}
NAMES = [f"p{i}" for i in range(30)] + ["next"] + [f"q{i}" for i in range(30)]
BASE = "http://example.com/go?" + "&".join(f"{name}=testing" for name in NAMES)
MATCHED = BASE.replace("next=testing", "next=//oast.me")


class _FakeNuclei:
    """Stands in for subprocess.check_output: the finding reproduces when the
    URL still has `next` and the template still has "//oast.me"."""

    def __init__(self) -> None:
        self.commands: List[List[str]] = []
        self.payloads: List[List[str]] = []

    def __call__(self, command: List[str], **kwargs: Any) -> bytes:
        self.commands.append(command)
        with open(command[command.index("-t") + 1]) as f:
            payloads = yaml.safe_load(f)["http"][0]["payloads"]["redirect"]
        self.payloads.append(payloads)
        return HIT if "next=" in command[command.index("-u") + 1] and "//oast.me" in payloads else b""


class TestReproducer(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.template_path = os.path.join(self.directory.name, "open-redirect-bypass.yaml")
        self._write(TEMPLATE)

    def _write(self, template: Dict[str, Any]) -> None:
        with open(self.template_path, "w") as f:
            yaml.safe_dump(template, f)

    def test_long_payload_list_narrowed_to_the_one_that_fires(self) -> None:
        fake = _FakeNuclei()
        with tempfile.TemporaryDirectory() as workdir, patch("artemis.modules.nuclei.subprocess.check_output", fake):
            reproducer = _Reproducer(self.template_path, workdir)
            self.assertTrue(reproducer(BASE))
            # About log2(32) re-fuzzes of halves, once per finding.
            self.assertLessEqual(len(fake.commands), 6)
            self.assertEqual(reproducer.describe(), f"payloads=1/{len(PAYLOADS)}")
            # Later checks carry only that payload: a miss costs one request.
            self.assertFalse(reproducer(BASE.replace("next=", "other=")))
            self.assertEqual(fake.payloads[-1], ["//oast.me"])

    def test_payloads_kept_as_nuclei_reads_them(self) -> None:
        """Read as YAML 1.1, a payload "yes" would be written back as true."""
        with open(self.template_path) as f:
            text = f.read()
        with open(self.template_path, "w") as f:
            f.write(text.replace("- 'yes'", "- yes"))
        fake = _FakeNuclei()
        with tempfile.TemporaryDirectory() as workdir, patch("artemis.modules.nuclei.subprocess.check_output", fake):
            _Reproducer(self.template_path, workdir)(BASE)
        self.assertIn("yes", fake.payloads[0] + fake.payloads[1])
        self.assertNotIn(True, fake.payloads[0] + fake.payloads[1])

    def test_short_payload_list_used_whole(self) -> None:
        short = dict(TEMPLATE, http=[dict(TEMPLATE["http"][0], payloads={"redirect": ["/x", "//oast.me"]})])
        self._write(short)
        fake = _FakeNuclei()
        with tempfile.TemporaryDirectory() as workdir, patch("artemis.modules.nuclei.subprocess.check_output", fake):
            reproducer = _Reproducer(self.template_path, workdir)
            self.assertTrue(reproducer(BASE))
        self.assertEqual([command[command.index("-t") + 1] for command in fake.commands], [self.template_path])
        self.assertEqual(reproducer.describe(), "")

    def test_target_that_stopped_reproducing_gets_the_whole_template(self) -> None:
        fake = _FakeNuclei()
        with tempfile.TemporaryDirectory() as workdir, patch("artemis.modules.nuclei.subprocess.check_output", fake):
            reproducer = _Reproducer(self.template_path, workdir)
            self.assertFalse(reproducer(BASE.replace("next=", "other=")))
        self.assertEqual(fake.commands[-1][fake.commands[-1].index("-t") + 1], self.template_path)
        self.assertEqual(reproducer.describe(), "")

    def test_whole_minimization(self) -> None:
        fake = _FakeNuclei()
        finding = {
            "template-id": "open-redirect-bypass",
            "template-path": self.template_path,
            "url": BASE,
            "matched-at": MATCHED,
        }
        with patch("artemis.modules.nuclei.subprocess.check_output", fake):
            with self.assertLogs("artemis.poc_minimization", level="INFO") as logs:
                result = _minimize_dast_finding(finding)
        self.assertEqual(result, "http://example.com/go?next=//oast.me")
        self.assertRegex(logs.output[-1], rf"params=61->1 outcome=shortened .* base=url payloads=1/{len(PAYLOADS)}$")
        # Subsets are re-fuzzed from the URL Nuclei fuzzed, with the original values.
        for command in fake.commands:
            self.assertNotIn("//oast.me", command[command.index("-u") + 1])

    def test_out_of_band_finding(self) -> None:
        """The evidence is a callback: every re-fuzz waits for one, and the
        search stops after a few halvings."""
        self._write(dict(TEMPLATE, http=[dict(TEMPLATE["http"][0], payloads={"redirect": ["{{interactsh-url}}"]})]))
        check_output = MagicMock(
            side_effect=lambda command, **kwargs: HIT if "next=" in command[command.index("-u") + 1] else b""
        )
        finding = {
            "template-id": "blind-ssrf",
            "template-path": self.template_path,
            "url": BASE,
            "matched-at": MATCHED,
            "interaction": {"protocol": "dns"},
        }
        with patch("artemis.modules.nuclei.subprocess.check_output", check_output):
            with self.assertLogs("artemis.poc_minimization", level="INFO") as logs:
                result = _minimize_dast_finding(finding)
        self.assertIn("next=//oast.me", result)
        self.assertLess(result.count("&"), 10)
        self.assertLessEqual(check_output.call_count, Config.Modules.Nuclei.NUCLEI_REFUZZ_OOB_MAX_CALLS_PER_FINDING)
        cooldown = Config.Modules.Nuclei.NUCLEI_REFUZZ_OOB_INTERACTIONS_COOLDOWN_SECONDS
        for call in check_output.call_args_list:
            command = call.args[0]
            self.assertEqual(command[command.index("-interactions-cooldown-period") + 1], str(cooldown))
            self.assertEqual(call.kwargs["timeout"], Config.Modules.Nuclei.NUCLEI_REFUZZ_TIMEOUT_SECONDS + cooldown)
        self.assertIn(" oob=1", logs.output[-1])


class TestUnexpectedErrors(unittest.TestCase):
    FINDING = {"template-id": "t", "template-path": "/nonexistent/t.yaml", "url": BASE, "matched-at": MATCHED}

    def test_finding_kept(self) -> None:
        with patch(
            "artemis.modules.nuclei.minimize_nuclei_matched_at_url", side_effect=ValueError("http://example.com/")
        ):
            with self.assertLogs("artemis.poc_minimization", level="WARNING") as logs:
                self.assertEqual(_minimize_dast_finding(dict(self.FINDING)), MATCHED)
        self.assertRegex(logs.output[0], r"PoC minimization failed: ValueError( at \S+:\d+)?$")
        self.assertNotIn("example.com", "".join(logs.output))

    def test_task_timeout_not_swallowed(self) -> None:
        """module_base ends a batch past TASK_TIMEOUT_SECONDS with
        timeout_decorator.TimeoutError - an Exception too."""
        with patch(
            "artemis.modules.nuclei.minimize_nuclei_matched_at_url", side_effect=timeout_decorator.TimeoutError()
        ):
            with self.assertRaises(timeout_decorator.TimeoutError):
                _minimize_dast_finding(dict(self.FINDING))


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


if __name__ == "__main__":
    unittest.main()
