import json
import logging
import re
import shutil
import tarfile
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

import requests

from artemis.config import Config

logger = logging.getLogger(__name__)

CHUNKS_SUBDIR = "nvdcpe-2.0-chunks"
INDEX_FILENAME = "title-index.json"
INDEX_CACHE: dict[Path, dict[str, str]] = {}
LOOKUP_CACHE: dict[tuple[Path, str], str | None] = {}


def get_nvd_dir() -> Path:
    return Path(Config.CpeDictionary.CPE_NVD_DIR).resolve()


def normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def family(cpe: str) -> str:
    # cpe:2.3:part:vendor:product -> the first five colon-separated components.
    return ":".join(cpe.split(":")[:5])


def _iter_entries(chunks_dir: Path) -> Iterator[tuple[str, str]]:
    for chunk in sorted(chunks_dir.glob("*.json")):
        try:
            with chunk.open("rb") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            logger.warning("Skipping unreadable CPE chunk %s", chunk)
            continue
        for product in data.get("products", []):
            cpe = product.get("cpe") or {}
            cpe_name = cpe.get("cpeName")
            if not isinstance(cpe_name, str):
                continue
            title = None
            for entry in cpe.get("titles", []):
                if isinstance(entry, dict) and entry.get("lang") == "en":
                    title = entry.get("title")
                    break
            if not title:
                continue
            yield cpe_name, title


def _build_index(chunks_dir: Path) -> dict[str, str]:
    # Normalized english title -> first CPE whose family matched that title.
    entries: dict[str, str] = {}
    for cpe_name, title in _iter_entries(chunks_dir):
        key = normalize(title)
        if not key or key in entries:
            continue
        entries[key] = cpe_name
    return entries


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


def ensure_index(nvd_dir: Path) -> dict[str, str]:
    cached = INDEX_CACHE.get(nvd_dir)
    if cached is not None:
        return cached

    chunks_dir = nvd_dir / CHUNKS_SUBDIR
    index_path = nvd_dir / INDEX_FILENAME
    index = _read_index_file(index_path)
    if index is None:
        if chunks_dir.is_dir():
            try:
                index = _build_index(chunks_dir)
            except Exception:  # never let a corrupt feed break scanning
                logger.exception("Failed to build CPE index from %s", chunks_dir)
                index = {}
        else:
            logger.warning(
                "NVD CPE dictionary not found under %s; CPE lookups will return None. "
                "Run `python3 -m artemis.cpe_tools.cpe_main_process` to download it.",
                nvd_dir,
            )
            index = {}
    INDEX_CACHE[nvd_dir] = index
    return index


def build_index(nvd_dir: Path | None = None) -> Path:
    directory = (Path(nvd_dir) if nvd_dir else get_nvd_dir()).resolve()
    chunks_dir = directory / CHUNKS_SUBDIR
    if not chunks_dir.is_dir():
        raise FileNotFoundError(f"CPE chunks directory not found: {chunks_dir}")

    entries = _build_index(chunks_dir)
    index_path = directory / INDEX_FILENAME
    _write_index_file(index_path, entries)

    INDEX_CACHE[directory] = entries
    return index_path


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
    INDEX_CACHE.clear()
    LOOKUP_CACHE.clear()
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
