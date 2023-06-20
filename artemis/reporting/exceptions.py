class TranslationNotFoundException(Exception):
    def __init__(self, message: str):
        self._message = message

    def __str__(self) -> str:
        return self._message
