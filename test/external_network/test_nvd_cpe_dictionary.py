import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from artemis.config import Config
from artemis.cpe_tools.cpe_main_process import (
    CHUNKS_SUBDIR,
    INDEX_TITLE_FILENAME,
    PLUGIN_INDEX_FILENAME,
    URL_INDEX_FILENAME,
    VERSION_FIELD_INDEX,
    VERSION_FILENAME,
    download_and_refresh,
    family,
    split_cpe,
)
from artemis.cpe_tools.cpe_utils import (
    lookup_cpe,
    lookup_cpe_by_plugin_slug,
    lookup_cpe_by_url,
)
from artemis.utils import build_logger

logger = build_logger(__name__)


class NvdCpeDictionaryEndToEndTest(unittest.TestCase):
    """Builds the CPE dictionary from the live NVD feed and looks products up in it."""

    nvd_dir: Path
    _tmp: "tempfile.TemporaryDirectory[str]"

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._tmp.cleanup)
        cls.nvd_dir = Path(cls._tmp.name)

        patcher = patch.object(Config.CpeDictionary, "CPE_NVD_DIR", str(cls.nvd_dir))
        patcher.start()
        cls.addClassCleanup(patcher.stop)

        assert lookup_cpe("WordPress") is None, "the scratch dictionary was not empty to begin with"

        started = time.monotonic()
        download_and_refresh()
        logger.info("Downloading and indexing the NVD CPE feed took %.0f s", time.monotonic() - started)

    def test_download_leaves_chunks_and_all_three_indices_on_disk(self) -> None:
        self.assertTrue((self.nvd_dir / CHUNKS_SUBDIR).is_dir())
        self.assertTrue(any((self.nvd_dir / CHUNKS_SUBDIR).glob("*.json")))
        for filename in (INDEX_TITLE_FILENAME, PLUGIN_INDEX_FILENAME, URL_INDEX_FILENAME, VERSION_FILENAME):
            with self.subTest(filename=filename):
                self.assertTrue((self.nvd_dir / filename).is_file())

    def test_title_lookup_resolves_wordpress(self) -> None:
        cpe = lookup_cpe("WordPress")

        self.assertIsNotNone(cpe)
        assert cpe is not None  # narrowing for the component access below
        self.assertEqual(family(cpe), "cpe:2.3:a:wordpress:wordpress")
        self.assertEqual(split_cpe(cpe)[VERSION_FIELD_INDEX], "*")

    def test_plugin_slug_lookup_resolves_contact_form_7(self) -> None:
        cpe = lookup_cpe_by_plugin_slug("contact-form-7", "wordpress")

        self.assertIsNotNone(cpe)
        assert cpe is not None  # narrowing for the component access below
        self.assertEqual(split_cpe(cpe)[4], "contact_form_7")
        self.assertEqual(split_cpe(cpe)[VERSION_FIELD_INDEX], "*")

    def test_url_lookup_resolves_a_plugin_page(self) -> None:
        # No reporter calls this yet, but it is the only thing exercising the url index -
        # without it, nothing would notice if _build_indices stopped writing one.
        cpe = lookup_cpe_by_url("https://wordpress.org/plugins/contact-form-7/")
        self.assertIsNotNone(cpe)
        assert cpe is not None  # narrowing for the component access below
        self.assertEqual(split_cpe(cpe)[4], "contact_form_7")
        self.assertEqual(split_cpe(cpe)[VERSION_FIELD_INDEX], "*")
