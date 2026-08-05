import unittest
from typing import Any, List

from artemis.reporting.base.cpe import to_cpe


class ToCPETest(unittest.TestCase):
    def test_cpe_2_3(self) -> None:
        self.assertEqual(
            to_cpe("cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"),
            "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
        )

    def test_cpe_2_2_uri(self) -> None:
        # A single Nuclei template still uses the old binding - let's not drop it.
        self.assertEqual(to_cpe("cpe:/a:redhat:infinispan"), "cpe:/a:redhat:infinispan")

    def test_surrounding_whitespace_is_stripped(self) -> None:
        self.assertEqual(to_cpe("  cpe:2.3:a:php:php:*:*:*:*:*:*:*:*\n"), "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*")

    def test_values_that_are_not_cpe_names(self) -> None:
        values: List[Any] = [
            None,
            "",
            "   ",
            "wordpress",
            # Looks CPE-ish, but is neither of the two bindings
            "cpe:whatever",
            "cpe:2.2:a:redhat:infinispan",
            # A bare prefix names no product
            "cpe:2.3:",
            "cpe:/",
            "  cpe:2.3:  ",
            # Not even a string - task results are JSON we don't control
            42,
            ["cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"],
            {"cpe": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"},
        ]
        for value in values:
            with self.subTest(value=value):
                self.assertIsNone(to_cpe(value))


if __name__ == "__main__":
    unittest.main()
