#!/usr/bin/env python3
"""Refresh extensions.json from live JED (Joomla Extensions Directory) data.

Individual extension failures (timeout, 404, parse error) are logged and skipped.
"""

import argparse
import datetime as _dt
import json
import logging
import os
import re
import sys
import time
from typing import Any, NamedTuple

import requests
from bs4 import BeautifulSoup, Tag

log = logging.getLogger("refresh_extensions")

JED_HOME = "https://extensions.joomla.org/"
DEFAULT_OUTPUT = "extensions.json"
DEFAULT_DELAY = 1.0
DEFAULT_RETRIES = 3
DEFAULT_TIMEOUT = 30
RECENT_URL = JED_HOME + "browse/recently-updated/extension/"
RECENT_PER_PAGE = 18

UA = "Mozilla/5.0 (compatible; joomla-scanner-refresh/1.0)"
HEADERS = {"User-Agent": UA, "Accept-Encoding": "identity"}

# Compatibility badge class -> joomla major version flag.
_COMPAT_BADGE = {"badge-30": "j3", "badge-40": "j4", "badge-50": "j5", "badge-60": "j6"}

_EXT_URL_RE = re.compile(r"/extension/([^/]+)/?$")
_ID_RE = re.compile(r"extension_id=(\d+)")
_JED_DATE_RE = re.compile(r"([A-Z][a-z]{2})\s+(\d{1,2}),?\s+(\d{4})")

Entry = dict[str, Any]
PageData = dict[str, Any]
ScrapeStatus = str


def _parse_jed_date(text: str | None) -> _dt.date | None:
    """Parse a JED 'Last updated' value (e.g. 'Sep 28 2026') to a date, or None."""
    if not text:
        return None
    m = _JED_DATE_RE.search(text)
    if not m:
        return None
    try:
        return _dt.datetime.strptime("%s %s %s" % m.groups(), "%b %d %Y").date()
    except ValueError:
        return None


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(HEADERS)
    return s


def http_get(
    session: requests.Session,
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
) -> tuple[int, str]:
    """GET with retries/backoff. Returns (status, body_text). Raises on final failure."""
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            r = session.get(url, timeout=timeout)
            return r.status_code, r.text
        except requests.RequestException as e:
            last_err = e
            if attempt < retries - 1:
                time.sleep(0.5 * (2**attempt))
    raise last_err if last_err else RuntimeError("http_get failed: " + url)


def fetch_sitemap_extension_urls(session: requests.Session, sitemap_url: str, limit: int | None = None) -> list[str]:
    _, body = http_get(session, sitemap_url)
    urls = re.findall(r"<loc>(.*?)</loc>", body)
    urls = [u.strip() for u in urls if "/extension/" in u and _EXT_URL_RE.search(u)]
    if limit:
        urls = urls[:limit]
    return urls


def fetch_recently_updated_urls(session: requests.Session) -> list[str]:
    urls = []
    seen = set()
    start = 0
    pages = 0
    while True:
        page_url = RECENT_URL + "?start=%d" % start
        try:
            status, html = http_get(session, page_url)
        except Exception as e:
            log.warning("failed to fetch %s: %s", page_url, e)
            break
        if status != 200 or not html:
            break
        soup = BeautifulSoup(html, "html.parser")
        cards = soup.select("div.extension.shadow-2")
        if not cards:
            break
        for card in cards:
            a = card.find("a", class_="extension-link")
            if not a or not isinstance(a, Tag):
                continue
            href = a.get("href", "")
            assert isinstance(href, str)
            slug = href.rstrip("/").rsplit("/", 1)[-1]
            if not slug or slug in seen:
                continue
            seen.add(slug)
            urls.append(JED_HOME + "extension/%s/" % slug)
        pages += 1
        log.info("recently-updated page %d: %d cards (start=%d)", pages, len(cards), start)
        next_start = start + RECENT_PER_PAGE
        if not soup.select_one('a.pagenav[href*="start=%d"]' % next_start):
            break
        start = next_start
    return urls


def load_extensions(path: str) -> tuple[list[Entry], str | None]:
    if not os.path.exists(path):
        return [], None
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (ValueError, OSError):
        return [], None
    return doc.get("extensions", []), doc.get("_fetch_date")


def parse_jed_page(html: str) -> PageData | None:
    """Return parsed fields from a JED extension page, or None if no meta block."""
    soup = BeautifulSoup(html, "html.parser")
    meta_dl = soup.select_one("#extension-meta")
    if meta_dl is None:
        return None

    name_el = meta_dl.find("h2")
    name = name_el.get_text(strip=True) if name_el else None

    meta: dict[str, str] = {}
    for dt in meta_dl.find_all("dt"):
        dd = dt.find_next_sibling("dd")
        if dd is None:
            continue
        key = dt.get_text(strip=True).rstrip(":").lower()
        text = dd.get_text(separator="\n", strip=True)
        if key:
            meta[key] = text

    def get(key: str) -> str | None:
        v = meta.get(key)
        return v.split("\n", 1)[0].strip() if v else None

    includes = {"component": False, "module": False, "plugin": False}
    includes_dt = meta_dl.find("dt", string=re.compile(r"Includes", re.I))
    if includes_dt is not None:
        dd = includes_dt.find_next_sibling("dd")
        if dd is not None and isinstance(dd, Tag):
            classes = " ".join(" ".join(span.get("class", [])) for span in dd.find_all("span"))
            if "badge-com" in classes:
                includes["component"] = True
            if "badge-mod" in classes:
                includes["module"] = True
            if "badge-plugin" in classes:
                includes["plugin"] = True

    compat = {"j3": False, "j4": False, "j5": False, "j6": False}
    compat_dt = meta_dl.find("dt", string=re.compile(r"Compatibility", re.I))
    if compat_dt is not None:
        dd = compat_dt.find_next_sibling("dd")
        if dd is not None and isinstance(dd, Tag):
            classes = " ".join(" ".join(span.get("class", [])) for span in dd.find_all("span"))
            for badge, flag in _COMPAT_BADGE.items():
                if badge in classes:
                    compat[flag] = True

    download_el = soup.select_one('a[data-role="download"]')
    install_url = download_el.get("href") if download_el else None

    extension_id = None
    m = _ID_RE.search(html)
    if m:
        extension_id = m.group(1)

    raw_type = get("type")
    ext_type = None
    if raw_type:
        low = raw_type.lower()
        if "paid" in low:
            ext_type = "Paid"
        elif "free" in low:
            ext_type = "Free"
        else:
            ext_type = raw_type

    return {
        "extension_name": name,
        "extension_id": extension_id,
        "latest_version": get("version"),
        "last_updated": get("last updated"),
        "date_added": get("date added"),
        "developer": get("developer"),
        "type": ext_type,
        "includes": includes,
        "joomla_compatibility": compat,
        "install_url": install_url,
    }


def build_entry(jed_url: str, page_data: PageData | None) -> Entry:
    """Build the flat output object from a JED page URL + scraped data."""
    entry = {
        "extension_name": None,
        "extension_id": None,
        "jed_url": jed_url,
        "install_url": None,
        "latest_version": None,
        "last_updated": None,
        "developer": None,
        "type": None,
        "includes": {"component": False, "module": False, "plugin": False},
        "joomla_compatibility": {"j3": False, "j4": False, "j5": False, "j6": False},
    }
    if page_data:
        for key in (
            "extension_name",
            "extension_id",
            "latest_version",
            "last_updated",
            "developer",
            "type",
            "includes",
            "joomla_compatibility",
            "install_url",
        ):
            if page_data.get(key) is not None:
                entry[key] = page_data[key]
    return entry


def write_output(path: str, entries: list[Entry], fetch_date: str) -> None:
    doc = {
        "_fetch_date": fetch_date,
        "extensions": entries,
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
        f.write("\n")
    os.replace(tmp, path)


class RefreshResult(NamedTuple):
    entries: list[Entry]
    scraped: int
    failed: int
    no_meta: int
    stopped: bool
    last_updated: Entry | None
    up_to_date: Entry | None


def _scrape_one(
    session: requests.Session,
    jed_url: str,
    timeout: int,
    retries: int,
) -> tuple[Entry, ScrapeStatus]:
    """Scrape a single JED extension page. Returns (entry, status) where
    status is 'ok', 'failed', or 'no_meta'."""
    try:
        status, html = http_get(session, jed_url, timeout=timeout, retries=retries)
        if status == 200 and html:
            page_data = parse_jed_page(html)
            if page_data is None:
                log.warning("no meta block for %s", jed_url)
                return build_entry(jed_url, None), "no_meta"
        else:
            log.warning("HTTP %s for %s", status, jed_url)
            return build_entry(jed_url, None), "failed"
    except Exception as e:
        log.warning("%s for %s", type(e).__name__, jed_url)
        return build_entry(jed_url, None), "failed"
    return build_entry(jed_url, page_data), "ok"


def scrape_extensions(
    session: requests.Session,
    urls: list[str],
    timeout: int,
    retries: int,
    delay: float,
) -> tuple[dict[str, Entry], int, int, int]:
    """Scrape a list of JED extension page URLs."""
    url_to_entry: dict[str, Entry] = {}
    failed = 0
    no_meta = 0
    for jed_url in urls:
        if jed_url in url_to_entry:
            continue
        entry, st = _scrape_one(session, jed_url, timeout, retries)
        if st == "failed":
            failed += 1
        elif st == "no_meta":
            no_meta += 1
            continue
        url_to_entry[jed_url] = entry
        time.sleep(delay)
    return url_to_entry, len(url_to_entry), failed, no_meta


def scrape_recent_extensions(
    session: requests.Session,
    urls: list[str],
    timeout: int,
    retries: int,
    delay: float,
    stop_date: _dt.date | None,
) -> tuple[dict[str, Entry], int, int, int, bool, Entry | None, Entry | None]:
    """Scrape recently-updated extension URLs (most-recent-first). Stops once
    an extension's ``last_updated`` is at or before ``stop_date``."""
    url_to_entry: dict[str, Entry] = {}
    failed = 0
    no_meta = 0
    stopped = False
    last_updated: Entry | None = None
    up_to_date: Entry | None = None
    for jed_url in urls:
        if jed_url in url_to_entry:
            continue
        entry, st = _scrape_one(session, jed_url, timeout, retries)
        if st == "failed":
            failed += 1
            continue
        elif st == "no_meta":
            no_meta += 1
            continue
        url_to_entry[jed_url] = entry
        time.sleep(delay)
        if stop_date is not None:
            ext_date = _parse_jed_date(entry.get("last_updated"))
            if ext_date is not None and ext_date < stop_date:
                up_to_date = entry
                stopped = True
                break
        last_updated = entry
    return (url_to_entry, len(url_to_entry), failed, no_meta, stopped, last_updated, up_to_date)


def run_full_refresh(session: requests.Session, args: argparse.Namespace) -> RefreshResult:
    """Full refresh from the JED sitemap"""
    sitemap_url = JED_HOME + "sitemap.xml"
    log.info("fetching extension list from sitemap...")
    urls = fetch_sitemap_extension_urls(session, sitemap_url, limit=args.limit)
    log.info("sitemap returned %d extension URLs", len(urls))

    url_to_entry, scraped, failed, no_meta = scrape_extensions(session, urls, args.timeout, args.retries, args.delay)
    entries = list(url_to_entry.values())
    return RefreshResult(entries, scraped, failed, no_meta, False, None, None)


def run_recent_refresh(session: requests.Session, args: argparse.Namespace) -> RefreshResult:
    """Incremental refresh from JED's 'recently updated' listing
    updates extensions.json."""
    existing, prev_fetch_date = load_extensions(args.output)
    stop_date: _dt.date | None = None
    if prev_fetch_date:
        try:
            stop_date = _dt.date.fromisoformat(prev_fetch_date)
        except ValueError:
            stop_date = None
    if stop_date:
        log.info("stopping at existing _fetch_date: %s", stop_date.isoformat())

    log.info("fetching recently-updated listing...")
    urls = fetch_recently_updated_urls(session)
    if args.limit:
        urls = urls[: args.limit]
    log.info("recently-updated returned %d extension URLs", len(urls))

    url_to_entry, scraped, failed, no_meta, stopped, last_updated, up_to_date = scrape_recent_extensions(
        session, urls, args.timeout, args.retries, args.delay, stop_date
    )

    existing_by_url: dict[str, Entry] = {e["jed_url"]: e for e in existing}
    existing_by_url.update(url_to_entry)
    entries = list(existing_by_url.values())
    return RefreshResult(entries, scraped, failed, no_meta, stopped, last_updated, up_to_date)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help="output path (default: %(default)s)")
    ap.add_argument(
        "--delay", type=float, default=DEFAULT_DELAY, help="seconds between JED page fetches (default: %(default)s)"
    )
    ap.add_argument(
        "--retries", type=int, default=DEFAULT_RETRIES, help="HTTP retries per request (default: %(default)s)"
    )
    ap.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT, help="per-request timeout in seconds (default: %(default)s)"
    )
    ap.add_argument("--limit", type=int, default=None, help="only fetch the first N extensions")
    ap.add_argument(
        "--recent",
        action="store_true",
        help="scrape only extensions listed in JED 'recently "
        "updated' pages and merge with existing output; stops "
        "early once it reaches extensions covered by _fetch_date",
    )
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )

    session = make_session()

    if args.recent:
        result = run_recent_refresh(session, args)
    else:
        result = run_full_refresh(session, args)

    result.entries.sort(key=lambda e: (int(e["extension_id"]) if str(e.get("extension_id", "")).isdigit() else 0))
    fetch_date = _dt.date.today().isoformat()
    write_output(args.output, result.entries, fetch_date)

    log.info("wrote %d extensions to %s (_fetch_date=%s)", len(result.entries), args.output, fetch_date)
    if args.recent:
        log.info(
            "scraped this run: %d | failed: %d | no-meta: %d | %s",
            result.scraped,
            result.failed,
            result.no_meta,
            "stopped early" if result.stopped else "reached end",
        )
        if result.last_updated is not None:
            log.info(
                "last updated: %s %s (%s)",
                result.last_updated.get("extension_name"),
                result.last_updated.get("latest_version"),
                result.last_updated.get("last_updated"),
            )
        if result.up_to_date is not None:
            log.info(
                "up to date: %s %s (%s)",
                result.up_to_date.get("extension_name"),
                result.up_to_date.get("latest_version"),
                result.up_to_date.get("last_updated"),
            )
    else:
        log.info("scraped this run: %d | failed: %d | no-meta: %d", result.scraped, result.failed, result.no_meta)
    return 0


if __name__ == "__main__":
    sys.exit(main())
