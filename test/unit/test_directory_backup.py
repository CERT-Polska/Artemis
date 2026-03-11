import logging
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock

from artemis.utils import directory_backup


class TestDirectoryBackup(unittest.TestCase):
    def setUp(self) -> None:
        self.test_root = tempfile.mkdtemp()
        self.logger = MagicMock(spec=logging.Logger)

    def tearDown(self) -> None:
        shutil.rmtree(self.test_root, ignore_errors=True)

    def _make_dir(self, name: str, files: dict[str, str] | None = None) -> str:
        """Create a subdirectory with optional files and return its path."""
        path = os.path.join(self.test_root, name)
        os.makedirs(path, exist_ok=True)
        for filename, content in (files or {}).items():
            with open(os.path.join(path, filename), "w") as f:
                f.write(content)
        return path

    def test_successful_operation_no_restore(self) -> None:
        """On success the original directory is left untouched."""
        d = self._make_dir("origdir", {"a.txt": "hello"})

        with directory_backup(d, logger=self.logger):
            pass

        self.assertTrue(os.path.isdir(d))
        with open(os.path.join(d, "a.txt")) as f:
            self.assertEqual(f.read(), "hello")

    def test_successful_overwrite_persists(self) -> None:
        """On success modified content persists and the backup is not restored."""
        d = self._make_dir("origdir", {"a.txt": "original", "b.txt": "keep"})

        with directory_backup(d, logger=self.logger):
            with open(os.path.join(d, "a.txt"), "w") as f:
                f.write("updated")
            os.remove(os.path.join(d, "b.txt"))
            with open(os.path.join(d, "c.txt"), "w") as f:
                f.write("new file")

        with open(os.path.join(d, "a.txt")) as f:
            self.assertEqual(f.read(), "updated")
        self.assertFalse(os.path.exists(os.path.join(d, "b.txt")))
        with open(os.path.join(d, "c.txt")) as f:
            self.assertEqual(f.read(), "new file")

    def test_restores_on_exception(self) -> None:
        """On failure the original directory is restored from backup."""
        d = self._make_dir("origdir", {"a.txt": "original"})

        with self.assertRaises(RuntimeError):
            with directory_backup(d, logger=self.logger):
                # Mutate the directory then fail
                with open(os.path.join(d, "a.txt"), "w") as f:
                    f.write("corrupted")
                os.makedirs(os.path.join(d, "subdir"))
                raise RuntimeError("boom")

        with open(os.path.join(d, "a.txt")) as f:
            self.assertEqual(f.read(), "original")
        self.assertFalse(os.path.exists(os.path.join(d, "subdir")))

    def test_exception_is_reraised(self) -> None:
        """The original exception propagates out of the context manager."""
        d = self._make_dir("origdir")

        with self.assertRaises(ValueError) as ctx:
            with directory_backup(d, logger=self.logger):
                raise ValueError("specific error")

        self.assertEqual(str(ctx.exception), "specific error")

    def test_multiple_directories(self) -> None:
        """Backup and restore works correctly with multiple directories."""
        d1 = self._make_dir("dir1", {"f1.txt": "content1"})
        d2 = self._make_dir("dir2", {"f2.txt": "content2"})

        with self.assertRaises(RuntimeError):
            with directory_backup(d1, d2, logger=self.logger):
                shutil.rmtree(d1)
                shutil.rmtree(d2)
                raise RuntimeError("boom")

        with open(os.path.join(d1, "f1.txt")) as f:
            self.assertEqual(f.read(), "content1")
        with open(os.path.join(d2, "f2.txt")) as f:
            self.assertEqual(f.read(), "content2")

    def test_nonexistent_directory_skipped(self) -> None:
        """A directory that doesn't exist at backup time is silently skipped."""
        missing = os.path.join(self.test_root, "no_such_dir")

        with directory_backup(missing, logger=self.logger):
            pass

        self.assertFalse(os.path.exists(missing))

    def test_preexisting_bak_is_overwritten(self) -> None:
        """A stale .bak directory is removed before creating a fresh backup."""
        d = self._make_dir("origdir", {"a.txt": "current"})
        stale_bak = d.rstrip("/") + ".bak"
        os.makedirs(stale_bak)
        with open(os.path.join(stale_bak, "a.txt"), "w") as f:
            f.write("stale")

        with directory_backup(d, logger=self.logger):
            pass

        # The stale backup should have been cleaned up in the finally block
        self.assertFalse(os.path.exists(stale_bak))

    def test_backup_cleaned_up_after_success(self) -> None:
        """.bak directories are removed in the finally block even on success."""
        d = self._make_dir("origdir", {"a.txt": "data"})
        bak_path = d.rstrip("/") + ".bak"

        with directory_backup(d, logger=self.logger):
            self.assertTrue(os.path.isdir(bak_path))

        self.assertFalse(os.path.exists(bak_path))

    def test_logger_called_on_failure(self) -> None:
        """logger.error is invoked when the wrapped operation fails."""
        d = self._make_dir("origdir")

        with self.assertRaises(RuntimeError):
            with directory_backup(d, logger=self.logger):
                raise RuntimeError("fail")

        self.logger.error.assert_called_once()
        args = self.logger.error.call_args[0]
        self.assertIn(d, args[1])


if __name__ == "__main__":
    unittest.main()
