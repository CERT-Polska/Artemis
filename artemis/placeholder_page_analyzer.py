import requests
from bs4 import BeautifulSoup

from artemis import http_requests


class PlaceholderPageAnalyzer:
    def __init__(self, url, keyword_provider):
        self.url = url
        self.keyword_provider = keyword_provider

    def analyze(self):
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
                except requests.RequestException as e:
                    return False
        soup = BeautifulSoup(response.text, 'html.parser')
        page_text = soup.get_text().lower()
        found_keywords = [keyword for keyword in self.keyword_provider.get_keywords() if keyword in page_text]

        if len(found_keywords) >= 1:
            return False
        return True


class KeywordProvider:
    def get_keywords(self):
        return [
            "trwa konserwacja",
            "dostawcą domeny jest",
            "domena utrzymywana",
            "domen dostępnych w",
            "automatycznie wygenerowane przez",
            "w trakcie wykonywania operacji wystąpił błąd",
            "wróć do bezpieczeństwa",
            "utrzymywana jest na serwerach",
            "parametry wspólne serwerów",
            "forbidden",
            "checking your browser",
            "strona w przygotowaniu",
            "strona w budowie",
            "strona jest w trakcie aktualizacji",
            "strona w budowie",
            "strona jest w trakcie aktualizacji",
            "strona tymczasowo niedostępna",
            "strona nie jest dostępna",
            "błąd 404",
            "błąd serwera",
            "przepraszamy za utrudnienia",
            "strona nie jest dostępna w tej chwili",
            "trwa konserwacja strony",
            "serwis jest chwilowo niedostępny",
            "już wkrótce wracamy",
            "strona będzie dostępna za chwilę",
            "zapraszamy do odwiedzenia nas później!",
            "strona będzie dostępna od",
            "planujemy powrót na",
            "pod tym adresem nie ma jeszcze żadnej strony",
            "jak kupić tę domenę",
            "zapytanie odrzucone przez serwer",
            "jest utrzymywana na serwerach"
        ]


class AnalyzerManager:
    def __init__(self, url):
        self.url = url
        self.keyword_provider = KeywordProvider()

    def run_analysis(self):
        analyzer = PlaceholderPageAnalyzer(self.url, self.keyword_provider)
        result = analyzer.analyze()
        return result
