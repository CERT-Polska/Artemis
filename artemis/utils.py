import logging


def build_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger


def is_directory_index(content: str) -> bool:
    return (
        "Index of /" in content
        or "ListBucketResult" in content
        or "<title>directory listing" in content.lower()
        or "<title>index of" in content.lower()
    )
