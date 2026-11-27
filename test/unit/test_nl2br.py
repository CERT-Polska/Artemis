import unittest

from artemis.reporting.export.main import create_environment


class Nl2brTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.template = create_environment().from_string("{{ value | nl2br }}")

    def test_preserves_distinct_lines_and_blank_lines(self) -> None:
        self.assertEqual(self.template.render(value="first\n\nlast"), "first<br>\n<br>\nlast")

    def test_empty_input(self) -> None:
        self.assertEqual(self.template.render(value=""), "")

    def test_newline_variants(self) -> None:
        for newline in ("\n", "\r\n", "\r"):
            with self.subTest(newline=newline):
                self.assertEqual(self.template.render(value=f"first{newline}last"), "first<br>\nlast")

    def test_strips_tags_and_escapes_text(self) -> None:
        self.assertEqual(self.template.render(value="<b>first</b>\nA & B"), "first<br>\nA &amp; B")

    def test_escapes_entities_without_double_escaping(self) -> None:
        self.assertEqual(self.template.render(value="A &amp; B\n2 &gt; 1"), "A &amp; B<br>\n2 &gt; 1")

    def test_strips_tags_from_each_line(self) -> None:
        self.assertEqual(
            self.template.render(value='<b>first</b>\n<img src=x onerror="alert(1)">\n<i>last</i>'),
            "first<br>\n<br>\nlast",
        )

    def test_rejects_remaining_angle_brackets_on_any_line(self) -> None:
        for value in (
            "&lt;img src=x onerror=alert(1)&gt;\nsafe",
            "safe\n&lt;img src=x onerror=alert(1)&gt;",
            "safe\n<unfinished",
        ):
            with self.subTest(value=value):
                self.assertEqual(self.template.render(value=value), "")

    def test_rejects_encoded_tags_in_every_line_position(self) -> None:
        for payload in (
            "&lt;img src=x onerror=alert(1)&gt;",
            "&#60;img src=x onerror=alert(1)&#62;",
            "&#x3c;img src=x onerror=alert(1)&#x3e;",
        ):
            for position in range(3):
                with self.subTest(payload=payload, position=position):
                    lines = ["first", "middle", "last"]
                    lines[position] = payload
                    self.assertEqual(self.template.render(value="\n".join(lines)), "")
