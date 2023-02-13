import logging
import subprocess
import sys
import time
from typing import Any, Callable, List

from artemis.config import Config


def check_output_and_print_content_on_error(command: List[str], **kwargs: Any) -> bytes:
    try:
        return subprocess.check_output(command, stderr=subprocess.PIPE, **kwargs)  # type: ignore
    except subprocess.CalledProcessError as e:
        sys.stderr.write(e.stderr.decode("ascii", errors="ignore") + "\n")
        raise


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


def throttle_request(f: Callable[[], Any]) -> Any:
    time_start = time.time()
    try:
        return f()
    finally:
        time_elapsed = time.time() - time_start
        if time_elapsed < Config.SECONDS_PER_REQUEST_FOR_ONE_IP:
            time.sleep(Config.SECONDS_PER_REQUEST_FOR_ONE_IP - time_elapsed)
