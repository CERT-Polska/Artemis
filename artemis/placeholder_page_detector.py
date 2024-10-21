from typing import Any

import requests

from artemis import http_requests
from artemis.config import Config

PLACEHOLDER_PAGE_CONTENT_FILENAME = Config.Modules.PlaceholderPageContent.PLACEHOLDER_PAGE_CONTENT_FILENAME


placeholder_page_content = []
with open(PLACEHOLDER_PAGE_CONTENT_FILENAME, "r", encoding="utf-8") as file:
    for keyword in file:
        placeholder_page_content.append(keyword)


class PlaceholderPageDetector:
    def __init__(self) -> None:
        self.placeholder_content = placeholder_page_content

    @staticmethod
    def check_response(domain: str) -> Any:
        if domain.startswith(("https://", "http://")):
            try:
                response = http_requests.get(domain)
            except requests.RequestException:
                return False
        else:
            url = "http://" + domain
            try:
                response = http_requests.get(url)
            except requests.RequestException:
                url = "https://" + domain
                try:
                    response = http_requests.get(url)
                except requests.RequestException:
                    return False
        response.encoding = "utf-8"
        return response

    def is_placeholder(self, domain: str) -> bool:
        response = self.check_response(domain)
        if response:
            html_content = response.content
            for keywords in self.placeholder_content:
                if keywords.strip() in html_content:
                    return True
        return False
