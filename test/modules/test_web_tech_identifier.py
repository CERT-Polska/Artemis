import unittest
from unittest.mock import patch, Mock
from artemis.modules.web_tech_identifier import WebtechIdentifier

class TestWebTechIdentifier(unittest.TestCase):
    def setUp(self):
        """Initialize the WebT\techIdentifier with test JSON data."""
        self.identifier = WebtechIdentifier("artemis/modules/data/web_tech_identifier_data.json")

    @patch("requests.get")
    def test_process(self, mock_get):
        """Test the process method with mocked HTTP response."""
        mock_response = Mock()
        mock_response.headers = {
            "Server": "Apache/2.4.25 (Debian)",
            "X-Powered-By": "PHP/5.6.40"
        }
        mock_response.cookies = [Mock(name="PHPSESSID")]
        mock_response.url = "http://example.com"
        mock_response.text = '<meta name="php" content="PHP 5.8">'
        
        mock_get.return_value = mock_response
        
        result = self.identifier.process(mock_response)
        
        expected_result = {
            "Apache HTTP Server": "2.4.25",
            "PHP": "5.6.40",
            "PHP": "Detected"
        }
        
        self.assertEqual(result, expected_result)

if __name__ == "__main__":
    unittest.main()
