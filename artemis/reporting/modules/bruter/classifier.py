import re
import urllib.parse

import bs4

from artemis.models import FoundURL


def is_password_file(found_url: FoundURL) -> bool:
    if ".pass" not in found_url.url and ".htpass" not in found_url.url:
        return False

    if _is_html(found_url.content_prefix):
        return False

    for line in found_url.content_prefix.split("\n"):
        # This checks whether the line begins with username: where username may contain letters, digits, - or _.
        if re.match("^[a-zA-Z0-9-_]*:", line):
            return True

    return False


def is_php_var_dump(found_url: FoundURL) -> bool:
    if " => " in found_url.content_prefix and (
        "array (" in found_url.content_prefix
        or "array(" in found_url.content_prefix
        or "Array\n" in found_url.content_prefix
    ):
        return True
    return False


def is_log_file(found_url: FoundURL) -> bool:
    path = urllib.parse.urlparse(found_url.url).path

    if "changelog" in path.lower():
        return False

    if "log" not in path and "/errors" not in path and "/debug" not in path:
        return False

    if found_url.has_directory_index:
        soup = bs4.BeautifulSoup(found_url.content_prefix)
        for link in soup.find_all("a"):
            href = link.get("href")
            if (
                "access.log" in href
                or "error.log" in href
                or "debug.log" in href
                or "access_log" in href
                or "error_log" in href
                or "debug_log" in href
                or "errors" in href
            ):
                return True

    if _is_html(found_url.content_prefix):
        return False

    match_strings = [
        "GET /",
        "HTTP/1.1",
        "Mozilla/5.0 (",
        "PHP Deprecated:",
        "PHP Warning:",
        "PHP Notice:",
        "PHP Fatal error:",
        "errno:",
        "Errcode",
    ]
    if any([match_string in found_url.content_prefix for match_string in match_strings]):
        return True

    return False


def is_sql_dump(found_url: FoundURL) -> bool:
    path = urllib.parse.urlparse(found_url.url).path
    if ".sql" not in path.lower() and "/sql" not in path.lower() and "/db" not in path.lower():
        return False

    if _is_html(found_url.content_prefix):
        return False

    if "sql dump" in found_url.content_prefix.lower():
        return True

    if "\ncreate table" in found_url.content_prefix.lower():
        return True

    return False


def is_ini_file(found_url: FoundURL) -> bool:
    path = urllib.parse.urlparse(found_url.url).path
    if ".ini" not in path.lower():
        return False

    if _is_html(found_url.content_prefix):
        return False

    for line in found_url.content_prefix.split("\n"):
        if line.strip().startswith("[") and line.strip().endswith("]"):
            return True

    return False


def is_configuration_file(found_url: FoundURL) -> bool:
    path = urllib.parse.urlparse(found_url.url).path
    if (
        "config" not in path.lower()
    ):  # let's assume everything that has config in the path is a config file: /config/prod.inc, /wp-config.php~ etc.
        return False

    if ".php" not in path and ".inc" not in path and ".phtml" not in path:  # .php covers .php, but also e.g. .php5
        return False

    if _is_html(found_url.content_prefix):
        return False

    if "<?php" in found_url.content_prefix:
        return True

    return False


def is_php_source(found_url: FoundURL) -> bool:
    path = urllib.parse.urlparse(found_url.url).path
    if ".php" not in path and ".inc" not in path and not path.endswith("/"):
        return False

    if "<?php" in found_url.content_prefix:
        return True

    return False


def is_dead_letter(found_url: FoundURL) -> bool:
    path = urllib.parse.urlparse(found_url.url).path
    if "dead.letter" not in path:
        return False

    if "Subject:" in found_url.content_prefix:
        return True

    if "Temat:" in found_url.content_prefix:  # TODO: add more translations
        return True

    return False


def contains_crypto_keys(found_url: FoundURL) -> bool:
    if _is_html(found_url.content_prefix):
        return False

    if "--BEGIN" in found_url.content_prefix and "PRIVATE KEY--" in found_url.content_prefix:
        return True

    return False


def is_exposed_file_with_listing(found_url: FoundURL) -> bool:
    if (
        "total " in found_url.content_prefix
        and "drwx" in found_url.content_prefix
        and not _is_html(found_url.content_prefix)
    ):  # ls results
        return True

    path = urllib.parse.urlparse(found_url.url).path
    if (
        ".listing" in path and "drwx" in found_url.content_prefix and "<html" not in found_url.content_prefix
    ):  # other type of listing
        return True

    if (
        path.strip("/") in found_url.content_prefix
        and "<PRE>" in found_url.content_prefix
        and "<html" not in found_url.content_prefix
    ):  # yet another results - let's make sure the file from path is in content
        return True

    return False


def is_exposed_archive(found_url: FoundURL) -> bool:
    if _is_html(found_url.content_prefix):
        return False

    path = urllib.parse.urlparse(found_url.url).path
    if ".zip" in path and found_url.content_prefix.startswith("PK"):
        return True

    # Let's allow gzip signature as well as we observe gzip files with tar extension
    if ".tar" in path and ("ustar" in found_url.content_prefix or found_url.content_prefix.startswith("\x1f")):
        return True

    if ".gz" in path and found_url.content_prefix.startswith("\x1f"):
        return True

    return False


def _is_html(content: str) -> bool:
    # If we have some HTML inside e.g. database dump, it's not a problem.
    # We don't want the file to *start* with HTML.
    content_prefix = content[:300]
    return "<html" in content_prefix.lower() or "<head" in content_prefix.lower() or "<body" in content_prefix.lower()
