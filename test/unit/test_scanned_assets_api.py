import unittest

from artemis.scanned_assets_api import is_output_line_correct


class TestIsOutputLineCorrect(unittest.TestCase):
    def test_endpoint_validation(self) -> None:
        for endpoint, valid, invalid in (
            ("get_subdomains", "WWW", "example.com/path"),
            ("get_parameters", "User_name-1.id", "user/name"),
            ("get_files", "/Path/file-name_1.txt", "/file?query=value"),
            ("get_admin_panel_urls", "/Admin/login.php", "https://example.com/admin"),
        ):
            with self.subTest(endpoint=endpoint):
                self.assertIs(is_output_line_correct(valid, endpoint), True)
                self.assertIs(is_output_line_correct(invalid, endpoint), False)

    def test_blank_lines_are_rejected(self) -> None:
        for line in ("", " ", "\t\n"):
            with self.subTest(line=line):
                self.assertIs(is_output_line_correct(line, "get_files"), False)

    def test_surrounding_whitespace_is_ignored_for_matching(self) -> None:
        self.assertIs(is_output_line_correct(" \texample.com\n", "get_subdomains"), True)
        self.assertIs(is_output_line_correct("example .com", "get_subdomains"), False)

    def test_length_limit_is_exclusive_and_includes_whitespace(self) -> None:
        for line, expected in (("a" * 29, True), ("a" * 30, False), ("a" * 31, False), (" " + "a" * 29, False)):
            with self.subTest(line=line):
                self.assertIs(is_output_line_correct(line, "get_files"), expected)

    def test_entire_line_must_match(self) -> None:
        for line in ("file!", "!file", "file\nname"):
            with self.subTest(line=line):
                self.assertIs(is_output_line_correct(line, "get_files"), False)

    def test_parameters_respect_default_length_limit(self) -> None:
        self.assertIs(is_output_line_correct("a" * 29, "get_parameters"), True)
        self.assertIs(is_output_line_correct("a" * 30, "get_parameters"), False)
