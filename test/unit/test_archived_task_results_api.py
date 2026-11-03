import gzip
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

from fastapi import FastAPI
from fastapi.testclient import TestClient

from artemis.api import router
from artemis.config import Config


class TestArchivedTaskResultsAPI(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.root = Path(temporary_directory.name)
        self.archives = self.root / "archives"
        self.archives.mkdir()
        self.filename = "2024-01-01_00_00_00-2024-01-02_00_00_00_tag_test.json.gz"
        self.results = [{"id": "task-id", "result": {"body": "archived result"}}]
        self.content = gzip.compress(json.dumps(self.results).encode())
        (self.archives / self.filename).write_bytes(self.content)
        output_path = patch.object(Config.Data.Autoarchiver, "AUTOARCHIVER_OUTPUT_PATH", str(self.archives))
        output_path.start()
        self.addCleanup(output_path.stop)
        token = patch.object(Config.Miscellaneous, "API_TOKEN", "archive-test-token")
        token.start()
        self.addCleanup(token.stop)
        app = FastAPI()
        app.include_router(router, prefix="/api")
        self.client = TestClient(app, headers={"X-API-Token": "archive-test-token"})
        self.addCleanup(self.client.close)
        self.url = "/api/archived-task-results"

    def test_list_download_and_delete_archive(self) -> None:
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [self.filename])

        response = self.client.get(f"{self.url}/{self.filename}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/gzip")
        self.assertIn("attachment;", response.headers["content-disposition"])
        self.assertIn(self.filename, response.headers["content-disposition"])
        self.assertEqual(response.content, self.content)
        self.assertEqual(json.loads(gzip.decompress(response.content)), self.results)

        response = self.client.delete(f"{self.url}/{self.filename}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True})
        self.assertFalse((self.archives / self.filename).exists())
        self.assertEqual(self.client.get(self.url).json(), [])
        for method in (self.client.get, self.client.delete):
            self.assertEqual(method(f"{self.url}/{self.filename}").status_code, 404)

    def test_list_is_sorted_and_ignores_unfinished_and_non_archive_files(self) -> None:
        (self.archives / "a.json.gz").write_bytes(self.content)
        for name in ("tmp_in_progress.json.gz", "notes.txt", ".hidden.json.gz"):
            (self.archives / name).write_text("not an archive")
        (self.archives / "directory.json.gz").mkdir()
        (self.archives / "nested").mkdir()
        (self.archives / "nested" / "nested.json.gz").write_bytes(self.content)
        self.assertEqual(self.client.get(self.url).json(), [self.filename, "a.json.gz"])
        for name in ("tmp_in_progress.json.gz", "notes.txt", ".hidden.json.gz", "directory.json.gz"):
            for method in (self.client.get, self.client.delete):
                with self.subTest(name=name, method=method.__name__):
                    self.assertEqual(method(f"{self.url}/{name}").status_code, 404)

    def test_missing_archive_directory(self) -> None:
        with patch.object(Config.Data.Autoarchiver, "AUTOARCHIVER_OUTPUT_PATH", str(self.root / "missing")):
            self.assertEqual(self.client.get(self.url).json(), [])
            for method in (self.client.get, self.client.delete):
                self.assertEqual(method(f"{self.url}/{self.filename}").status_code, 404)

    def test_archive_filename_with_spaces_and_unicode(self) -> None:
        filename = "2024-01-01_00_00_00-2024-01-02_00_00_00_tag_zażółć space.json.gz"
        (self.archives / filename).write_bytes(self.content)
        self.assertIn(filename, self.client.get(self.url).json())
        url = f"{self.url}/{quote(filename, safe='')}"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, self.content)
        self.assertEqual(self.client.delete(url).status_code, 200)
        self.assertFalse((self.archives / filename).exists())

    def test_cannot_access_files_outside_archive_directory(self) -> None:
        outside = self.root / "outside.json.gz"
        outside.write_bytes(self.content)
        (self.archives / "link.json.gz").symlink_to(outside)
        (self.archives / "broken.json.gz").symlink_to(self.root / "missing.json.gz")
        self.assertEqual(self.client.get(self.url).json(), [self.filename])
        for name in (
            "link.json.gz",
            "broken.json.gz",
            "..%2Foutside.json.gz",
            "%2Foutside.json.gz",
            "nested%2F..%2F..%2Foutside.json.gz",
            "..%5Coutside.json.gz",
        ):
            for method in (self.client.get, self.client.delete):
                with self.subTest(name=name, method=method.__name__):
                    self.assertEqual(method(f"{self.url}/{name}").status_code, 404)
        self.assertEqual(outside.read_bytes(), self.content)
        self.assertTrue((self.archives / "link.json.gz").is_symlink())

    def test_all_endpoints_require_valid_api_token(self) -> None:
        for headers, status in (({}, 422), ({"X-API-Token": "wrong"}, 401)):
            with TestClient(self.client.app, headers=headers) as client:
                for method, url in (
                    (client.get, self.url),
                    (client.get, f"{self.url}/{self.filename}"),
                    (client.delete, f"{self.url}/{self.filename}"),
                ):
                    with self.subTest(headers=headers, method=method.__name__, url=url):
                        self.assertEqual(method(url).status_code, status)
        self.assertTrue((self.archives / self.filename).is_file())

    def test_api_disabled_without_configured_token(self) -> None:
        with patch.object(Config.Miscellaneous, "API_TOKEN", ""):
            for method, url in (
                (self.client.get, self.url),
                (self.client.get, f"{self.url}/{self.filename}"),
                (self.client.delete, f"{self.url}/{self.filename}"),
            ):
                self.assertEqual(method(url).status_code, 401)
