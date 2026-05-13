import unittest

from artemis.reporting.export.main import _add_cve_link_to_rendered_html_body


class CVEAddTestCase(unittest.TestCase):
    def test_cve_add(self) -> None:
        input_html = "This is a vulnerability: CVE-2021-12345. And another one: CVE-2020-54321."
        expected_output = (
            'This is a vulnerability: <a href="https://www.cve.org/CVERecord?id=CVE-2021-12345">CVE-2021-12345</a>. '
            'And another one: <a href="https://www.cve.org/CVERecord?id=CVE-2020-54321">CVE-2020-54321</a>.'
        )
        self.assertEqual(_add_cve_link_to_rendered_html_body(input_html), expected_output)

    def test_nothing_added_inside_links(self) -> None:
        input_html = 'This is a link: <a href="https://example.com">CVE-2021-12345</a>.'
        expected_output = 'This is a link: <a href="https://example.com">CVE-2021-12345</a>.'
        self.assertEqual(_add_cve_link_to_rendered_html_body(input_html), expected_output)

    def test_nothing_added_inside_script(self) -> None:
        input_html = '<script>var cve = "CVE-2021-12345";</script>'
        expected_output = '<script>var cve = "CVE-2021-12345";</script>'
        self.assertEqual(_add_cve_link_to_rendered_html_body(input_html), expected_output)

    def test_nothing_added_inside_style(self) -> None:
        input_html = '<style>.cve { content: "CVE-2021-12345"; }</style>'
        expected_output = '<style>.cve { content: "CVE-2021-12345"; }</style>'
        self.assertEqual(_add_cve_link_to_rendered_html_body(input_html), expected_output)

    def test_case_sensitivity(self) -> None:
        input_html = "This is a vulnerability: cve-2021-12345."
        self.assertEqual(
            _add_cve_link_to_rendered_html_body(input_html), input_html
        )  # CVE should be uppercase to be recognized

    def test_not_full_cve_pattern(self) -> None:
        input_html = "This is not a CVE: CVE-2021-123."
        self.assertEqual(
            _add_cve_link_to_rendered_html_body(input_html), input_html
        )  # Not a full CVE pattern, should not be linked
