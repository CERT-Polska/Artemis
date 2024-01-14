import unittest

from artemis.modules import humble


class TestProcessJsonData(unittest.TestCase):
    def test_process_json_data_with_valid_input(self) -> None:
        # Setup
        input_data = {
            "[0. Info]": {"Date": "1970/01/01 - 12:12:12", "URL": "https://test.tld"},
            "[1. Missing HTTP Security Headers]": ["Cache-Control", "Clear-Site-Data", "Cross-Origin-Embedder-Policy"],
            "[2. Fingerprint HTTP Response Headers]": [
                "Server",
            ],
            "[3. Deprecated HTTP Response Headers/Protocols and Insecure Values]": ["X-XSS-Protection (Unsafe Value)"],
            "[4. Empty HTTP Response Headers Values]": ["Content-Security-Policy"],
            "[5. Browser Compatibility for Enabled HTTP Security Headers]": {
                "X-XSS-Protection": "https://caniuse.com/?search=X-XSS-Protection"
            },
        }

        # Exercise
        result = humble.process_json_data(input_data)

        # Verify
        expected_result = [
            humble.Message(
                category="Missing http security headers",
                problems=["Cache-Control", "Clear-Site-Data", "Cross-Origin-Embedder-Policy"],
            )
        ]
        self.assertEqual(result, expected_result)


if __name__ == "__main__":
    unittest.main()
