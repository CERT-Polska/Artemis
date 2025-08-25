import os
import unittest

from artemis.utils import add_common_params_from_wordlist


class TestAddCommonParamsFromWordlist(unittest.TestCase):
    def test_add_common_params_from_wordlist(self) -> None:
        url = "http://example.com/test?param1=value1"
        params_file = os.path.join(os.path.dirname(__file__), "../data/wordlists/test_wordlist.txt")
        modified_url = add_common_params_from_wordlist(url, params_file, "abcd.html")
        with open(params_file, "r") as file:
            params = file.read().splitlines()
            params = [param.strip() for param in params if param.strip() and not param.startswith("#")]

        expected_url = "http://example.com/test?param1=value1&" + "&".join(f"{param}=abcd.html" for param in params)

        self.assertEqual(modified_url, expected_url)
