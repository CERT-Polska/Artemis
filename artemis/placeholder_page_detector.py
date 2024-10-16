from typing import Any

import requests

from artemis import http_requests
from artemis.config import Config


class PlaceholderPageAnalyzer:
    def __init__(self, url: str) -> None:
        self.url = url

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

    def is_placeholder(self) -> bool:
        response = self.check_response()
        if response:
            html_content = response.content
            with open(
                Config.Modules.PlaceholderPageContent.PLACEHOLDER_PAGE_CONTENT_FILENAME, "r", encoding="utf-8"
            ) as file:
                for keyword in file:
                    if keyword.strip() in html_content:
                        return False
        return True


class PlaceholderPageDetector:
    def __init__(self, url: str) -> None:
        self.url = url

    def run_analysis(self) -> bool:
        placeholder_detector = PlaceholderPageAnalyzer(self.url)
        result = placeholder_detector.is_placeholder()

        return result
