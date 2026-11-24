import glob
import os
import tempfile
import unittest
from typing import Any, Callable, Dict, List

import yaml

from artemis.modules import nuclei_refuzz_templates as templates
from artemis.modules.nuclei import NUCLEI_TEMPLATES_LOCATION
from artemis.reporting.modules.nuclei.poc_url_utils import align_query_pairs

# The parts of dast/vulnerabilities/redirect/open-redirect-bypass.yaml that
# matter here: payloads with DSL, two fuzzing rules, a header matcher on an
# oast.me canary - but no interactsh.
OPEN_REDIRECT_BYPASS = """
id: open-redirect-bypass
info:
  name: Open Redirect Bypass
  severity: medium
http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'
    payloads:
      redirect:
        - "{{Hostname}}.oast.me"
        - "//oast.me"
        - '////oast.me'
        - "//oast%E3%80%82me"
        - "{{RootURL}}/http://www.oast.me/"
        - '{{RootURL}}oast.me'
        - 'oast.me'
    fuzzing:
      - parts:
          - query
        mode: single
        keys:
          - next
          - url
        fuzz:
          - "{{redirect}}"
      - parts:
          - query
        mode: single
        values:
          - "https?://"
        fuzz:
          - "{{redirect}}"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: regex
        part: header
        regex:
          - '(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/)(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.me\\/?(\\/|[^.].*)?$'
      - type: status
        status:
          - 302
"""

SQLI_ERROR_BASED = """
id: sqli-error-based
info:
  name: SQLi
  severity: critical
http:
  - payloads:
      injection:
        - "'"
        - "\\""
        - ";"
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{injection}}"
    stop-at-first-match: true
    matchers:
      - type: regex
        regex:
          - "SQL syntax.{0,500}?MySQL"
"""

RESPONSE_SSRF = """
id: response-ssrf
info:
  name: Response SSRF
  severity: high
http:
  - payloads:
      ssrf:
        - 'http://{{interactsh-url}}'
        - 'http://{{FQDN}}.{{interactsh-url}}'
        - 'file:////./etc/./passwd'
    fuzzing:
      - part: query
        mode: single
        keys:
          - url
        fuzz:
          - "{{ssrf}}"
    stop-at-first-match: true
    matchers-condition: or
    matchers:
      - type: word
        part: body
        words:
          - "Interactsh Server"
      - type: regex
        part: body
        regex:
          - 'root:.*?:[0-9]*:[0-9]*:'
"""


def _template(text: str) -> Dict[str, Any]:
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(text)
    try:
        return templates.load_template(f.name)
    finally:
        os.unlink(f.name)


BASE = "http://e.com/go?next=http%3A%2F%2F127.0.0.1%2Fabc.html&url=http%3A%2F%2F127.0.0.1%2Fabc.html&id=testing"


class TestFindMatchingPayloads(unittest.TestCase):
    def _find(self, template: str, matched: str, base: str = BASE) -> Any:
        aligned = align_query_pairs(base, matched)
        assert aligned is not None
        return templates.find_matching_payloads(_template(template), aligned)

    def test_replace(self) -> None:
        name, entries, all_entries = self._find(
            OPEN_REDIRECT_BYPASS, "http://e.com/go?next=//oast.me&url=//oast.me&id=testing"
        )
        self.assertEqual(name, "redirect")
        # {{RootURL}}oast.me can evaluate to //oast.me too.
        self.assertEqual(entries, ["//oast.me", "{{RootURL}}oast.me"])
        self.assertEqual(len(all_entries), 7)

    def test_dsl_and_encoded_payloads(self) -> None:
        self.assertEqual(
            self._find(OPEN_REDIRECT_BYPASS, "http://e.com/go?next=e.com.oast.me&url=e.com.oast.me&id=testing")[1],
            ["{{Hostname}}.oast.me", "{{RootURL}}oast.me"],
        )
        self.assertEqual(
            self._find(OPEN_REDIRECT_BYPASS, "http://e.com/go?next=//oast%E3%80%82me&url=//oast%E3%80%82me&id=testing")[
                1
            ],
            ["//oast%E3%80%82me"],
        )

    def test_postfix(self) -> None:
        name, entries, _ = self._find(
            SQLI_ERROR_BASED,
            "http://e.com/go?next=http%3A%2F%2F127.0.0.1%2Fabc.html%22&url=http%3A%2F%2F127.0.0.1%2Fabc.html%22"
            "&id=testing%22",
        )
        self.assertEqual((name, entries), ("injection", ['"']))

    def test_payload_with_interactsh_url(self) -> None:
        self.assertEqual(
            self._find(
                RESPONSE_SSRF,
                "http://e.com/go?next=http%3A%2F%2F127.0.0.1%2Fabc.html&url=http://d4f8a2c1b0e9.oast.fun&id=testing",
            )[1],
            ["http://{{interactsh-url}}", "http://{{FQDN}}.{{interactsh-url}}"],
        )

    def test_nothing_fits(self) -> None:
        self.assertIsNone(self._find(SQLI_ERROR_BASED, "http://e.com/go?next=x&url=x&id=testingXYZ"))

    def test_nothing_changed(self) -> None:
        self.assertIsNone(self._find(SQLI_ERROR_BASED, BASE))

    def test_shapes_not_narrowed(self) -> None:
        matched = "http://e.com/go?next=http%3A%2F%2F127.0.0.1%2Fabc.html%27&url=x&id=testing%27"
        aligned = align_query_pairs(BASE, matched)
        assert aligned is not None
        changes: List[Callable[[Dict[str, Any]], None]] = [
            # a wordlist file
            lambda request: request.update(payloads={"injection": "payloads/sqli.txt"}),
            # two payload sets (pitchfork, clusterbomb)
            lambda request: request["payloads"].update(other=["a", "b"]),
            # a non-string payload
            lambda request: request.update(payloads={"injection": ["'", 5]}),
        ]
        for change in changes:
            template = _template(SQLI_ERROR_BASED)
            change(template["http"][0])
            self.assertIsNone(templates.find_matching_payloads(template, aligned))

    def test_aggression_levels(self) -> None:
        template = _template(SQLI_ERROR_BASED)
        template["http"][0]["payloads"] = {"injection": {"low": ["'", '"'], "medium": [";"]}}
        aligned = align_query_pairs(BASE, BASE.replace("testing", "testing%27"))
        assert aligned is not None
        # Nuclei runs with -fuzz-aggression low: ";" is not even sent.
        self.assertEqual(templates.find_matching_payloads(template, aligned), ("injection", ["'"], ["'", '"']))


class TestNarrowedTemplate(unittest.TestCase):
    def test_with_payloads(self) -> None:
        template = _template(OPEN_REDIRECT_BYPASS)
        narrowed = templates.with_payloads(template, "redirect", ["//oast.me"])
        self.assertEqual(narrowed["http"][0]["payloads"], {"redirect": ["//oast.me"]})
        # Everything else stays, and the original is untouched.
        self.assertEqual(narrowed["http"][0]["matchers"], template["http"][0]["matchers"])
        self.assertEqual(narrowed["http"][0]["fuzzing"], template["http"][0]["fuzzing"])
        self.assertEqual(len(template["http"][0]["payloads"]["redirect"]), 7)

    def test_written_template_reads_back_the_same(self) -> None:
        template = _template(OPEN_REDIRECT_BYPASS)
        with tempfile.TemporaryDirectory() as directory:
            path = templates.write_template(template, directory, "narrowed")
            self.assertEqual(templates.load_template(path), template)
            with open(path) as f:
                # The digest of the original would no longer match.
                self.assertNotIn("digest", f.read())

    def test_yaml_1_2_scalars(self) -> None:
        """A payload "yes" or "on" is a string to Nuclei; read as YAML 1.1 it
        would come back from the dump as a boolean."""
        template = _template(
            "id: t\nhttp:\n  - payloads:\n      p: [yes, on, 'no', 1:20, 10, true]\n    stop-at-first-match: true\n"
        )
        self.assertEqual(template["http"][0]["payloads"]["p"], ["yes", "on", "no", "1:20", 10, True])
        self.assertIs(template["http"][0]["stop-at-first-match"], True)
        with tempfile.TemporaryDirectory() as directory:
            with open(templates.write_template(template, directory, "t")) as f:
                # As Go's YAML would read it.
                self.assertEqual(yaml.safe_load(f)["http"][0]["payloads"]["p"], ["yes", "on", "no", "1:20", 10, True])

    def test_needs_interactsh(self) -> None:
        self.assertFalse(templates.needs_interactsh(_template(OPEN_REDIRECT_BYPASS)))
        response_ssrf = _template(RESPONSE_SSRF)
        self.assertTrue(templates.needs_interactsh(response_ssrf))
        self.assertFalse(
            templates.needs_interactsh(templates.with_payloads(response_ssrf, "ssrf", ["file:////./etc/./passwd"]))
        )


@unittest.skipUnless(
    os.path.isdir(os.path.join(NUCLEI_TEMPLATES_LOCATION, "dast")), "the Nuclei templates are not installed"
)
class TestRealTemplates(unittest.TestCase):
    """The installed Nuclei templates (in the test image)."""

    def _path(self, relative: str) -> str:
        return os.path.join(NUCLEI_TEMPLATES_LOCATION, relative)

    def test_every_dast_template_survives_a_rewrite(self) -> None:
        for path in glob.glob(self._path("dast/**/*.yaml"), recursive=True):
            template = templates.load_template(path)
            with tempfile.TemporaryDirectory() as directory:
                self.assertEqual(
                    templates.load_template(templates.write_template(template, directory, "copy")), template, path
                )

    def test_open_redirect_bypass_narrowed_to_the_hit(self) -> None:
        template = templates.load_template(self._path("dast/vulnerabilities/redirect/open-redirect-bypass.yaml"))
        aligned = align_query_pairs(BASE, BASE.replace("http%3A%2F%2F127.0.0.1%2Fabc.html", "//oast.me"))
        assert aligned is not None
        match = templates.find_matching_payloads(template, aligned)
        assert match is not None
        self.assertIn("//oast.me", match[1])
        self.assertLessEqual(len(match[1]), 3)
        self.assertGreater(len(match[2]), 100)


if __name__ == "__main__":
    unittest.main()
