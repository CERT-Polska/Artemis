import json
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple
from urllib.request import urlopen

from artemis.config import Config
from artemis.cpe_tools.cpe_main_process import (
    _extract_refs,
    _iter_entries,
    split_cpe,
    title_key,
)
from artemis.cpe_tools.cpe_plugin_slug import plugin_slug

DOWNLOAD_TIMEOUT_SECONDS = 300

# A cpe:2.3 name is the binding prefix plus eleven fields.
CPE_2_3_COMPONENTS = 13

# The feed is a third-party dataset with the occasional oddity in it, so the checks below are on
# proportions rather than on every single entry - a canary that goes red because one name out of
# 140 000 is malformed is a canary somebody disables. A change of format takes these numbers to zero,
# not to 98%.
DOMINANT = 0.99


def _download_first_chunk(destination: Path) -> Path:
    """Downloads the feed tarball and unpacks only its first chunk into ``destination``.

    The whole archive is hundreds of megabytes and every chunk has the same shape, so it is read as a
    stream and the connection is dropped as soon as one chunk is out.
    """
    url = Config.CpeDictionary.CPE_NVD_DOWNLOAD_URL
    with urlopen(url, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
        with tarfile.open(fileobj=response, mode="r|gz") as tar:
            for member in tar:
                if not member.name.endswith(".json"):
                    continue
                source = tar.extractfile(member)
                if source is None:
                    continue
                chunk = destination / Path(member.name).name
                with chunk.open("wb") as f:
                    shutil.copyfileobj(source, f)
                return chunk
    raise AssertionError(f"No .json chunk in the CPE feed downloaded from {url}")


class NvdCpeFeedShapeTest(unittest.TestCase):
    """Checks that the real NVD feed still has the shape ``artemis.cpe_tools`` parses."""

    data: Dict[str, Any]
    products: List[Dict[str, Any]]
    chunks_dir: Path
    _tmp: "tempfile.TemporaryDirectory[str]"

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.chunks_dir = Path(cls._tmp.name)
        chunk = _download_first_chunk(cls.chunks_dir)
        with chunk.open("rb") as f:
            cls.data = json.load(f)
        cls.products = cls.data["products"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def test_chunk_is_a_list_of_products(self) -> None:
        self.assertIsInstance(self.data.get("products"), list)
        # ~140 000 products per chunk as of 2026-09.
        self.assertGreater(len(self.products), 1000)
        self.assertTrue(all(isinstance(product.get("cpe"), dict) for product in self.products))

    def test_cpe_names_split_into_the_fields_the_code_indexes(self) -> None:
        names = [product["cpe"].get("cpeName") for product in self.products]
        self.assertTrue(all(isinstance(name, str) for name in names))

        lengths = [len(split_cpe(name)) for name in names]
        self.assertGreater(sum(1 for n in lengths if n == CPE_2_3_COMPONENTS) / len(lengths), DOMINANT)

    def test_titles_carry_an_english_entry(self) -> None:
        well_formed = 0
        english = 0
        for product in self.products:
            titles = product["cpe"].get("titles")
            if not isinstance(titles, list) or not titles:
                continue
            if all(isinstance(entry, dict) and "title" in entry and "lang" in entry for entry in titles):
                well_formed += 1
            if any(isinstance(entry, dict) and str(entry.get("lang", "")).lower().startswith("en") for entry in titles):
                english += 1

        self.assertGreater(well_formed / len(self.products), DOMINANT)
        self.assertGreater(english / len(self.products), DOMINANT)

    def test_refs_are_mappings_carrying_a_url(self) -> None:
        with_refs = [product["cpe"] for product in self.products if product["cpe"].get("refs")]
        self.assertGreater(len(with_refs), 1000)

        entries = [ref for cpe in with_refs for ref in cpe["refs"]]
        carrying_a_url = sum(1 for ref in entries if isinstance(ref, dict) and isinstance(ref.get("ref"), str))
        self.assertGreater(carrying_a_url / len(entries), DOMINANT)
        self.assertTrue(all(_extract_refs(cpe) for cpe in with_refs))

    def test_deprecated_is_a_boolean_flag(self) -> None:
        flags = [product["cpe"].get("deprecated") for product in self.products]
        self.assertGreater(sum(1 for flag in flags if isinstance(flag, bool)) / len(flags), DOMINANT)
        self.assertGreater(sum(1 for flag in flags if flag is True), 0)
        self.assertGreater(sum(1 for flag in flags if flag is False), 0)

    def test_iter_entries_yields_entries_the_title_index_can_key(self) -> None:
        total = 0
        keyed = 0
        trimmed = 0
        for cpe_name, title, _refs in _iter_entries(self.chunks_dir):
            total += 1
            key, names_a_product = title_key(title, cpe_name)
            if key:
                keyed += 1
            if not names_a_product:
                trimmed += 1

        self.assertGreater(total, 1000)
        self.assertLess(total, len(self.products))
        self.assertGreater(keyed / total, DOMINANT)
        self.assertGreater(trimmed / total, 0.5)

    def test_wordpress_plugin_slugs_are_still_published(self) -> None:
        slugs: Set[Tuple[str, str]] = set()
        for _cpe_name, _title, refs in _iter_entries(self.chunks_dir):
            for url in refs:
                cms_slug = plugin_slug(url)
                if cms_slug is not None:
                    slugs.add(cms_slug)
        self.assertGreater(len(slugs), 50)
        self.assertTrue(all(cms == "wordpress" for cms, _ in slugs))
