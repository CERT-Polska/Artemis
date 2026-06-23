import datetime
import gzip
import json
import os
import shutil
import tempfile
import unittest
import uuid
from contextlib import contextmanager
from typing import Any, Generator, Iterator
from unittest.mock import patch

from artemis.autoarchiver.autoarchiver import (
    _save_and_delete_items,
    archive_old_results,
    archive_tag,
)
from artemis.db import DB, TaskResult


def _read_gz(path: str) -> list[Any]:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return list(json.load(f))


class TestAutoArchiver(unittest.TestCase):
    def _make_result(self, id: str, created_at: datetime.datetime, body: str = "x") -> dict[str, Any]:
        return {"id": id, "created_at": created_at, "result": {"body": body}}

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_simple(self) -> None:
        items = [
            self._make_result("a", datetime.datetime(2024, 1, 1)),
            self._make_result("b", datetime.datetime(2024, 1, 2)),
            self._make_result("c", datetime.datetime(2024, 1, 3)),
        ]
        with patch("artemis.autoarchiver.autoarchiver.db"), patch(
            "artemis.autoarchiver.autoarchiver.Config"
        ) as mock_cfg:
            mock_cfg.Data.Autoarchiver.AUTOARCHIVER_OUTPUT_PATH = self.tmpdir
            result = _save_and_delete_items(iter(items), "_test")

        self.assertEqual(result, 3)

        # file_verification
        gz_files = [f for f in os.listdir(self.tmpdir) if f.endswith(".json.gz")]
        self.assertEqual(len(gz_files), 1)
        data = _read_gz(os.path.join(self.tmpdir, gz_files[0]))
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 3)
        self.assertEqual(data[0]["id"], "a")
        self.assertEqual(data[1]["id"], "b")
        self.assertEqual(data[2]["id"], "c")

        # tempfile deletion
        leftover = [f for f in os.listdir(self.tmpdir) if f.startswith("tmp_")]
        self.assertEqual(leftover, [])

    def test_cleanup_on_write_error(self) -> None:
        def bad_iterator() -> Iterator[dict[str, Any]]:
            yield self._make_result("a", datetime.datetime(2024, 1, 1))
            raise RuntimeError("simulated DB failure mid-stream")

        with patch("artemis.autoarchiver.autoarchiver.db") as mock_db, patch(
            "artemis.autoarchiver.autoarchiver.Config"
        ) as mock_cfg:
            mock_cfg.Data.Autoarchiver.AUTOARCHIVER_OUTPUT_PATH = self.tmpdir
            with self.assertRaises(RuntimeError):
                _save_and_delete_items(bad_iterator(), "_test")

        self.assertEqual(os.listdir(self.tmpdir), [])
        mock_db.delete_task_results_by_ids.assert_not_called()


def _insert_task_result(db: DB, *, tag: str, status: str, age_days: int = 60) -> str:
    row_id = str(uuid.uuid4())
    created_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=age_days)
    with db.session() as session:
        session.add(
            TaskResult(
                id=row_id,
                analysis_id=str(uuid.uuid4()),
                created_at=created_at,
                status=status,
                tag=tag,
                receiver="test_receiver",
                target_string="target.example.com",
                headers_string="receiver test_receiver",
                task={
                    "uid": row_id,
                    "root_uid": str(uuid.uuid4()),
                    "headers": {},
                    "payload": {},
                    "payload_persistent": {},
                },
                result={"body": "test-body"},
                additional_info={},
            )
        )
        session.commit()
    return row_id


def _ids_in_db_with_tag(db: DB, tag: str) -> set[str]:
    with db.session() as session:
        return {row.id for row in session.query(TaskResult).filter(TaskResult.tag == tag).all()}


class TestAutoArchiverWithDB(unittest.TestCase):
    def setUp(self) -> None:
        self.db = DB()
        self.tmpdir = tempfile.mkdtemp()
        self.tag = f"autoarchiver_test_{uuid.uuid4().hex}"

    def tearDown(self) -> None:
        with self.db.session() as session:
            session.query(TaskResult).filter(TaskResult.tag.like("autoarchiver_test_%")).delete(
                synchronize_session=False
            )
            session.commit()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @contextmanager
    def _patch_config(self, pack_size: int, min_age_seconds: int = 1) -> Generator[None, None, None]:
        with patch("artemis.autoarchiver.autoarchiver.Config") as mock_cfg:
            mock_cfg.Data.Autoarchiver.AUTOARCHIVER_OUTPUT_PATH = self.tmpdir
            mock_cfg.Data.Autoarchiver.AUTOARCHIVER_PACK_SIZE = pack_size
            mock_cfg.Data.Autoarchiver.AUTOARCHIVER_MIN_AGE_SECONDS_INTERESTING = min_age_seconds
            mock_cfg.Data.Autoarchiver.AUTOARCHIVER_MIN_AGE_SECONDS_NOT_INTERESTING = min_age_seconds
            yield

    def test_archive_old_results_only_archives_matching_interesting_flag(self) -> None:
        interesting_id_1 = _insert_task_result(self.db, tag=self.tag, status="INTERESTING", age_days=60)
        interesting_id_2 = _insert_task_result(self.db, tag=self.tag, status="INTERESTING", age_days=60)
        ok_id_1 = _insert_task_result(self.db, tag=self.tag, status="OK", age_days=60)

        with self._patch_config(pack_size=2, min_age_seconds=1):
            archive_old_results(interesting=True)

        remaining = _ids_in_db_with_tag(self.db, self.tag)
        self.assertNotIn(interesting_id_1, remaining)
        self.assertNotIn(interesting_id_2, remaining)
        self.assertIn(ok_id_1, remaining)

        gz_files = [f for f in os.listdir(self.tmpdir) if f.endswith(".json.gz")]
        self.assertEqual(len(gz_files), 1)
        data = _read_gz(os.path.join(self.tmpdir, gz_files[0]))
        archived_ids = {item["id"] for item in data}
        self.assertEqual(archived_ids, {interesting_id_1, interesting_id_2})
        for item in data:
            self.assertEqual(item["result"]["body"], "test-body")

    def test_archive_old_results_only_archives_matching_not_interesting_flag(self) -> None:
        ok_id_1 = _insert_task_result(self.db, tag=self.tag, status="OK", age_days=60)
        ok_id_2 = _insert_task_result(self.db, tag=self.tag, status="OK", age_days=60)
        interesting_id_1 = _insert_task_result(self.db, tag=self.tag, status="INTERESTING", age_days=60)

        with self._patch_config(pack_size=2, min_age_seconds=1):
            archive_old_results(interesting=False)

        remaining = _ids_in_db_with_tag(self.db, self.tag)
        self.assertNotIn(ok_id_1, remaining)
        self.assertNotIn(ok_id_2, remaining)
        self.assertIn(interesting_id_1, remaining)

        gz_files = [f for f in os.listdir(self.tmpdir) if f.endswith(".json.gz")]
        self.assertEqual(len(gz_files), 1)
        data = _read_gz(os.path.join(self.tmpdir, gz_files[0]))
        archived_ids = {item["id"] for item in data}
        self.assertEqual(archived_ids, {ok_id_1, ok_id_2})
        for item in data:
            self.assertEqual(item["result"]["body"], "test-body")

    def test_archive_old_results_does_not_archive_when_min_count_not_reached(self) -> None:
        inserted_ids = {_insert_task_result(self.db, tag=self.tag, status="OK", age_days=60) for _ in range(3)}

        with self._patch_config(pack_size=5, min_age_seconds=1):
            archive_old_results(interesting=False)

        self.assertEqual(_ids_in_db_with_tag(self.db, self.tag), inserted_ids)
        self.assertEqual([f for f in os.listdir(self.tmpdir) if f.endswith(".json.gz")], [])

    def test_archive_tag_only_archives_rows_with_matching_tag(self) -> None:
        {_insert_task_result(self.db, tag=self.tag, status="OK") for _ in range(3)}

        other_tag = self.tag + "_other"
        other_ids = {_insert_task_result(self.db, tag=other_tag, status="OK") for _ in range(3)}

        with self._patch_config(pack_size=100):
            archive_tag(self.tag)

        self.assertEqual(_ids_in_db_with_tag(self.db, self.tag), set())
        self.assertEqual(_ids_in_db_with_tag(self.db, other_tag), other_ids)


if __name__ == "__main__":
    unittest.main()
