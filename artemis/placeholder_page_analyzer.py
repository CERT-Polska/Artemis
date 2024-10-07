from typing import List

import requests
from bs4 import BeautifulSoup

from artemis import http_requests
from artemis.config import Config


class PlaceholderPageAnalyzer:
    def __init__(self, url: str, keyword_provider: List[str]) -> None:
        self.url = url
        self.keyword_provider = keyword_provider

    def check_response(self):
        if self.url.startswith(("https://", "http://")):
            response = http_requests.get(self.url)
        else:
            self.url = "http://" + self.url
            try:
                response = http_requests.get(self.url)
            except requests.exceptions.HTTPError:
                self.url = "https://" + self.url
                try:
                    response = http_requests.get(self.url)
                except requests.RequestException:
                    return False
        return response

    def analyze(self) -> bool:
        response = self.check_response()
        if response:
            soup = BeautifulSoup(response.text, "html.parser")
            meta_description = soup.find('meta', attrs={'name': 'description'}).get('content')

            if meta_description:
                expected_meta = 'Strona utrzymywana na serwerach home.pl'
                actual_meta = str(meta_description)

                if actual_meta.strip() == expected_meta:
                    return False
                else:
                    return True
            return True
        return False


class AnalyzerManager:
    def __init__(self, url: str) -> None:
        self.url = url
        self.keyword_provider = Config.Modules.PlaceholderPagesHtmlElements.PLACEHOLDER_PAGE_HTML_ELEMENTS

    def run_analysis(self) -> bool:
        analyzer = PlaceholderPageAnalyzer(self.url, self.keyword_provider)
        result = analyzer.analyze()
        return result
