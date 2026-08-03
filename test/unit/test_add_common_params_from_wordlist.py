import os
import unittest
from unittest.mock import patch

from artemis.crawling import add_injectable_params_and_common_params_from_wordlist


class TestAddCommonParamsFromWordlist(unittest.TestCase):
    @patch("artemis.crawling.get_injectable_parameters", return_value=[])
    def test_add_injectable_params_and_common_params_from_wordlist(
        self, _mock_get_injectable_parameters: object
    ) -> None:
        url = "http://example.com/test?param1=value1"
        params_file = os.path.join(os.path.dirname(__file__), "../data/wordlists/test_wordlist.txt")
        modified_url = add_injectable_params_and_common_params_from_wordlist(url, params_file, "abcd.html")
        with open(params_file, "r") as file:
            params = file.read().splitlines()
            params = [param.strip() for param in params if param.strip() and not param.startswith("#")]

        for param in params:
            self.assertTrue(f"{param}=abcd.html" in modified_url)
