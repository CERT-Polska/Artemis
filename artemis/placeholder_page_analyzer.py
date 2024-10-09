from typing import Any, List

import requests

from artemis import http_requests
from artemis.config import Config


class PlaceholderPageAnalyzer:
    def __init__(self, url: str, keyword_provider: List[str]) -> None:
        self.url = url
        self.keyword_provider = keyword_provider

    def check_response(self) -> Any:
        if self.url.startswith(("https://", "http://")):
            try:
                response = http_requests.get(self.url)
            except requests.RequestException:
                return False
        else:
            url = "http://" + self.url
            try:
                response = http_requests.get(url)
            except requests.RequestException:
                url = "https://" + self.url
                try:
                    response = http_requests.get(url)
                except requests.RequestException:
                    return False
        response.encoding = "utf-8"
        return response

    def analyze(self) -> bool:
        response = self.check_response()
        if response:
            html_content = response.content
            for keyword in self.keyword_provider:
                if keyword in html_content:
                    return False
        return True


class AnalyzerManager:
    def __init__(self, url: str) -> None:
        self.url = url
        self.keyword_provider = Config.Modules.PlaceholderPagesHtmlElements.PLACEHOLDER_PAGE_HTML_ELEMENTS

    def run_analysis(self) -> bool:
        analyzer = PlaceholderPageAnalyzer(self.url, self.keyword_provider)
        result = analyzer.analyze()

        return result
