import urllib
from typing import List

from bs4 import BeautifulSoup

from artemis import http_requests


def get_links_and_resources_on_same_domain(url: str) -> List[str]:
    url_parsed = urllib.parse.urlparse(url)
    response = http_requests.get(url)
    soup = BeautifulSoup(response.text)
    links = []
    for tag in soup.find_all():
        new_url = None
        for attribute in ["src", "href"]:
            if attribute not in tag.attrs:
                continue

            new_url = urllib.parse.urljoin(url, tag[attribute])
            new_url_parsed = urllib.parse.urlparse(new_url)

            # Let's be lax and allow resources from different ports (or e.g. http vs https)
            if url_parsed.hostname == new_url_parsed.hostname:
                links.append(new_url.split("#")[0])
    return list(set(links))
