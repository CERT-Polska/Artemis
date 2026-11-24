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

BLIND_SSRF = """
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
        mode: single
        values:
          - "https?://"
        fuzz:
          - "https://{{ssrf}}"
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
"""

SSTI_DSL_OOB = """
id: jinja2-oob
info:
  name: Jinja2 OOB
  severity: high
http:
  - payloads:
      injection:
        - "{{self.__init__.__globals__.__builtins__.__import__('os').popen('nslookup {{interactsh-url}}').read()}}"
    fuzzing:
      - part: query
        type: postfix
        fuzz:
          - "{{injection}}"
    matchers:
      - type: dsl
        dsl:
          - "contains(interactsh_protocol,'dns')"
"""


def _template(text: str) -> Dict[str, Any]:
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(text)
    try:
        return templates.load_template(f.name)
    finally:
        os.unlink(f.name)


BASE = "http://e.com/go?next=http%3A%2F%2F127.0.0.1%2Fabc.html&url=http%3A%2F%2F127.0.0.1%2Fabc.html&id=testing"


class TestClassification(unittest.TestCase):
    def test_in_band(self) -> None:
        self.assertFalse(templates.uses_interactsh_matchers(_template(OPEN_REDIRECT_BYPASS)))
        self.assertFalse(templates.uses_interactsh_matchers(_template(SQLI_ERROR_BASED)))

    def test_interactsh_url_in_payloads_is_not_oob(self) -> None:
        """response-ssrf sends an OAST URL, but its evidence is the response."""
        self.assertFalse(templates.uses_interactsh_matchers(_template(RESPONSE_SSRF)))

    def test_oob(self) -> None:
        self.assertTrue(templates.uses_interactsh_matchers(_template(BLIND_SSRF)))
        self.assertTrue(templates.uses_interactsh_matchers(_template(SSTI_DSL_OOB)))


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


BLIND_OAST_POLYGLOTS = """
id: cmdi-blind-oast-polyglot
info:
  name: Blind OAST polyglots
  severity: high
variables:
  marker: "{{interactsh-url}}"
http:
  - payloads:
      payload:
        - "&nslookup {{marker}}&'"
        - "1;nslookup${IFS}{{marker}};#${IFS}'"
        - "$(ping -c 1 {{marker}} | nslookup {{marker}})"
        - "$(ping -c 1 {{marker}} | nslookup {{marker}})"
        - "$(id)"
    fuzzing:
      - parts:
          - query
        type: postfix
        fuzz:
          - "{{payload}}"
    stop-at-first-match: true
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "dns"
"""


class TestOobCanaryTemplate(unittest.TestCase):
    def test_payload_moved_into_the_fuzz_expression(self) -> None:
        """Nuclei renders a payload once per payload - the same OAST URL in
        every parameter - but the fuzz expression once per parameter."""
        canary = templates.oob_canary_template(_template(BLIND_SSRF))
        assert canary is not None
        request = canary["http"][0]
        self.assertNotIn("payloads", request)
        self.assertEqual(request["fuzzing"][0]["fuzz"], ["https://{{interactsh-url}}"])
        self.assertEqual(request["matchers"], _template(BLIND_SSRF)["http"][0]["matchers"])
        self.assertEqual(templates.fuzz_value_count(canary), 1)

    def test_url_variable_inlined(self) -> None:
        """A variable holding the OAST URL is one URL for the whole run."""
        canary = templates.oob_canary_template(_template(BLIND_OAST_POLYGLOTS))
        assert canary is not None
        # "$(id)" sends no OAST URL, the duplicate is sent once; a raw "&" and
        # "#" are fine.
        self.assertEqual(
            canary["http"][0]["fuzzing"][0]["fuzz"],
            [
                "&nslookup {{interactsh-url}}&'",
                "1;nslookup${IFS}{{interactsh-url}};#${IFS}'",
                "$(ping -c 1 {{interactsh-url}} | nslookup {{interactsh-url}})",
            ],
        )

    def test_only_the_identified_payloads(self) -> None:
        template = _template(SSTI_DSL_OOB)
        template["http"][0]["payloads"]["injection"].append("${{interactsh-url}}")
        canary = templates.oob_canary_template(template, ["${{interactsh-url}}"])
        assert canary is not None
        self.assertEqual(canary["http"][0]["fuzzing"][0]["fuzz"], ["${{interactsh-url}}"])
        # Nested expressions of an SSTI payload stay as they are.
        canary = templates.oob_canary_template(template)
        assert canary is not None
        self.assertEqual(canary["http"][0]["fuzzing"][0]["fuzz"][0], template["http"][0]["payloads"]["injection"][0])

    def test_unsupported(self) -> None:
        function_wrapped = _template(BLIND_SSRF)
        function_wrapped["http"][0]["fuzzing"][0]["fuzz"] = ["{{url_encode(ssrf)}}"]
        no_oast = _template(BLIND_OAST_POLYGLOTS)
        no_oast["http"][0]["payloads"]["payload"] = ["$(id)"]
        two_sets = _template(BLIND_SSRF)
        two_sets["http"][0]["payloads"]["other"] = ["x"]
        for template in (function_wrapped, no_oast, two_sets):
            self.assertIsNone(templates.oob_canary_template(template))
        self.assertIsNone(templates.oob_canary_template(_template(BLIND_SSRF), ["not a payload of it"]))


@unittest.skipUnless(
    os.path.isdir(os.path.join(NUCLEI_TEMPLATES_LOCATION, "dast")), "the Nuclei templates are not installed"
)
class TestRealTemplates(unittest.TestCase):
    """The installed Nuclei templates (in the test image)."""

    def _path(self, relative: str) -> str:
        return os.path.join(NUCLEI_TEMPLATES_LOCATION, relative)

    def test_classification(self) -> None:
        for in_band in (
            "dast/vulnerabilities/redirect/open-redirect-bypass.yaml",
            "dast/vulnerabilities/ssrf/response-ssrf.yaml",
            "dast/vulnerabilities/xss/reflected-xss.yaml",
            "dast/vulnerabilities/sqli/sqli-error-based.yaml",
        ):
            self.assertFalse(templates.uses_interactsh_matchers(templates.load_template(self._path(in_band))), in_band)
        oob = ["dast/vulnerabilities/ssrf/blind-ssrf.yaml"] + glob.glob(
            self._path("dast/vulnerabilities/ssti/oob/*.yaml")
        )
        for path in oob:
            self.assertTrue(templates.uses_interactsh_matchers(templates.load_template(self._path(path))), path)

    def test_every_dast_template_survives_a_rewrite(self) -> None:
        for path in glob.glob(self._path("dast/**/*.yaml"), recursive=True):
            template = templates.load_template(path)
            with tempfile.TemporaryDirectory() as directory:
                self.assertEqual(
                    templates.load_template(templates.write_template(template, directory, "copy")), template, path
                )

    def test_oob_canaries(self) -> None:
        supported = 0
        for path in glob.glob(self._path("dast/vulnerabilities/**/*.yaml"), recursive=True):
            template = templates.load_template(path)
            if not templates.uses_interactsh_matchers(template):
                continue
            canary = templates.oob_canary_template(template)
            # Every OOB finding is to be shortened: no template is skipped.
            assert canary is not None, path
            supported += 1
            (request,) = [request for request in canary["http"] if request.get("fuzzing")]
            self.assertNotIn("payloads", request, path)
            for rule in request["fuzzing"]:
                for expression in rule["fuzz"]:
                    self.assertIn("{{interactsh-url}}", expression, path)
        self.assertGreater(supported, 20)

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
