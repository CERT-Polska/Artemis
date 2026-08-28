import hashlib
import json
import re
import shutil
import tarfile
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import requests

from artemis.config import Config
from artemis.cpe_tools.cpe_plugin_slug import plugin_slug
from artemis.utils import build_logger

logger = build_logger(__name__)

CHUNKS_SUBDIR = "nvdcpe-2.0-chunks"
INDEX_TITLE_FILENAME = "title-index.json"
PLUGIN_INDEX_FILENAME = "plugin-index.json"
URL_INDEX_FILENAME = "url-index.json"
VERSION_FILENAME = "index-version.json"

TITLE = "title"
PLUGIN = "plugin"
URL = "url"
_INDEX_KINDS = {TITLE: INDEX_TITLE_FILENAME, PLUGIN: PLUGIN_INDEX_FILENAME, URL: URL_INDEX_FILENAME}

# Per-kind, per-directory index caches holding the parsed index data. Each entry is
# a (version-token, dict) pair.
INDEX_CACHE: dict[str, dict[Path, tuple[str, dict[str, str]]]] = {kind: {} for kind in _INDEX_KINDS}


def split_cpe(cpe: str) -> list[str]:
    return re.split(r"(?<!\\):", cpe)


def get_nvd_dir() -> Path:
    return Path(Config.CpeDictionary.CPE_NVD_DIR).resolve()


def normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path.rstrip("/"), parts.query, ""))


def family(cpe: str) -> str:
    # cpe:2.3:part:vendor:product -> the first five colon-separated components.
    return ":".join(split_cpe(cpe)[:5])


def _extract_refs(cpe: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    for ref in cpe.get("refs") or []:
        if isinstance(ref, str):
            urls.append(ref)
        elif isinstance(ref, dict):
            url = ref.get("ref") or ref.get(URL)
            if isinstance(url, str):
                urls.append(url)
    return urls


def _strip_sw_edition(cpe_name: str) -> str:
    SW_EDITION_FIELD_INDEX = 9
    parts = split_cpe(cpe_name)
    if len(parts) > SW_EDITION_FIELD_INDEX:
        parts[SW_EDITION_FIELD_INDEX] = "*"
        return ":".join(parts)
    return cpe_name


def _iter_entries(chunks_dir: Path) -> Iterator[tuple[str, str, list[str]]]:
    for chunk in sorted(chunks_dir.glob("*.json")):
        try:
            with chunk.open("rb") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            logger.warning("Skipping unreadable CPE chunk %s", chunk)
            continue
        for product in data.get("products", []):
            cpe = product.get("cpe") or {}
            if cpe.get("deprecated"):
                continue
            cpe_name = cpe.get("cpeName")
            if not isinstance(cpe_name, str):
                continue
            title = None
            for entry in cpe.get("titles", []):
                if (
                    isinstance(entry, dict)
                    and entry.get("lang") is not None
                    and entry.get("lang").lower().startswith("en")  # type: ignore
                ):
                    title = entry.get(TITLE)
                    break
            if not title:
                continue
            yield cpe_name, title, _extract_refs(cpe)


def _build_indices(chunks_dir: Path) -> dict[str, dict[str, str]]:
    titles: dict[str, str] = {}
    plugins: dict[str, str] = {}
    urls: dict[str, str] = {}
    for cpe_name, title, refs in _iter_entries(chunks_dir):
        cpe = _strip_sw_edition(cpe_name)
        key = normalize(title)
        if key and key not in titles:
            titles[key] = cpe
        for url in refs:
            cms_slug = plugin_slug(url)
            if cms_slug is not None:
                cms, slug = cms_slug
                pkey = f"{cms}:{slug}"
                if pkey not in plugins:
                    plugins[pkey] = cpe
            url_key = normalize_url(url)
            if url_key and url_key not in urls:
                urls[url_key] = cpe
    return {TITLE: titles, PLUGIN: plugins, URL: urls}


def build_version_token(*dicts: dict[str, str]) -> str:
    h = hashlib.sha256()
    for m in dicts:
        h.update(json.dumps(m, sort_keys=True, separators=(",", ":")).encode())
    return h.hexdigest()


def read_version_token(directory: Path) -> str:
    version_path = directory / VERSION_FILENAME
    try:
        with version_path.open("rb") as f:
            payload = json.load(f)
        if isinstance(payload, dict):
            token = payload.get("hash")
            if isinstance(token, str):
                return token
    except (OSError, json.JSONDecodeError):
        pass
    return ""


def ensure_version_token(directory: Path) -> str:
    token = read_version_token(directory)
    if token:
        return token
    return ""


def _read_index_file(index_path: Path) -> dict[str, str] | None:
    try:
        with index_path.open("rb") as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _write_index_file(index_path: Path, entries: dict[str, str]) -> None:
    tmp_path = index_path.with_name(index_path.name + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(entries, f)
    tmp_path.replace(index_path)


def _ensure_index(nvd_dir: Path, kind: str) -> dict[str, str]:
    cache = INDEX_CACHE[kind]
    version = ensure_version_token(nvd_dir)
    cached = cache.get(nvd_dir)
    if cached is not None and cached[0] == version:
        return cached[1]

    chunks_dir = nvd_dir / CHUNKS_SUBDIR
    index = _read_index_file(nvd_dir / _INDEX_KINDS[kind])
    if index is None:
        if chunks_dir.is_dir():
            try:
                index = _build_indices(chunks_dir)[kind]
            except Exception:
                logger.exception("Failed to build %s index from %s", kind, chunks_dir)
                index = {}
        else:
            index = {}
            if kind == TITLE:
                logger.warning(
                    "NVD CPE dictionary not found under %s; CPE lookups will return None. "
                    "Run `python3 -m artemis.cpe_tools.cpe_main_process` to download it.",
                    nvd_dir,
                )

    cache[nvd_dir] = (version, index)
    return index


def ensure_title_index(nvd_dir: Path) -> dict[str, str]:
    return _ensure_index(nvd_dir, TITLE)


def ensure_plugin_index(nvd_dir: Path) -> dict[str, str]:
    return _ensure_index(nvd_dir, PLUGIN)


def ensure_url_index(nvd_dir: Path) -> dict[str, str]:
    return _ensure_index(nvd_dir, URL)


def build_index(nvd_dir: Path | None = None) -> Path:
    directory = (Path(nvd_dir) if nvd_dir else get_nvd_dir()).resolve()
    chunks_dir = directory / CHUNKS_SUBDIR
    if not chunks_dir.is_dir():
        raise FileNotFoundError(f"CPE chunks directory not found: {chunks_dir}")

    indices = _build_indices(chunks_dir)
    for kind, filename in _INDEX_KINDS.items():
        _write_index_file(directory / filename, indices[kind])
    _write_index_file(
        directory / VERSION_FILENAME, {"hash": build_version_token(indices[TITLE], indices[PLUGIN], indices[URL])}
    )

    return directory / INDEX_TITLE_FILENAME


def download_and_refresh(nvd_dir: Path | None = None) -> None:
    directory = (Path(nvd_dir) if nvd_dir else get_nvd_dir()).resolve()
    url = Config.CpeDictionary.CPE_NVD_DOWNLOAD_URL
    chunks_dst = directory / CHUNKS_SUBDIR

    directory.mkdir(parents=True, exist_ok=True)
    logger.info("Downloading NVD CPE database from %s", url)

    with tempfile.TemporaryDirectory(dir=directory) as tmp_str:
        tmp_dir = Path(tmp_str)
        tarball = tmp_dir / "nvdcpe.tar.gz"

        with requests.get(url, stream=True, timeout=(30, 1800)) as response:
            response.raise_for_status()
            with tarball.open("wb") as f:
                for chunk in response.iter_content(chunk_size=65536):
                    f.write(chunk)

        extract_dir = tmp_dir / "extracted"
        extract_dir.mkdir()
        with tarfile.open(tarball) as tar:
            safe_members = [
                m for m in tar.getmembers() if not Path(m.name).is_absolute() and ".." not in Path(m.name).parts
            ]
            tar.extractall(extract_dir, members=safe_members)
        tarball.unlink()

        candidates = list(extract_dir.rglob(CHUNKS_SUBDIR))
        if not candidates:
            raise FileNotFoundError(f"'{CHUNKS_SUBDIR}' directory not found in tarball downloaded from {url}")
        new_chunks = candidates[0]

        if chunks_dst.exists():
            shutil.rmtree(chunks_dst)
        shutil.move(str(new_chunks), str(chunks_dst))

    try:
        build_index(directory)
    except Exception:
        logger.exception("Failed to build CPE index after download from %s", url)
    logger.info("NVD CPE database refreshed at %s", directory)


def main() -> None:
    logger.info("Service started")
    interval = Config.CpeDictionary.CPE_NVD_REFRESH_INTERVAL_SECONDS
    chunks_dir = get_nvd_dir() / CHUNKS_SUBDIR
    while True:
        stale = not chunks_dir.is_dir() or chunks_dir.stat().st_mtime < time.time() - interval
        if stale:
            try:
                download_and_refresh()
            except Exception:
                logger.exception("NVD CPE refresh failed")
        logger.info("Sleeping %d seconds until next NVD CPE refresh", interval)
        time.sleep(interval)


if __name__ == "__main__":
    main()
