import datetime
import unittest
from typing import Any

from artemis.karton_utils import (
    MIN_ANALYSIS_AGE_TO_BE_CONSIDERED_FINISHED,
    is_analysis_finished,
)
from artemis.task_utils import (
    ARTEMIS_ANALYSIS_FINISHED_AT_KEY_PREFIX,
    delete_analysis_finished_time,
    get_analysis_finished_time,
    set_analysis_finished_time,
)


class FakeRedis:
    def __init__(self) -> None:
        self.data: dict[str, bytes] = {}

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.data[key] = value.encode("utf-8")

    def get(self, key: str) -> bytes | None:
        return self.data.get(key)

    def delete(self, *keys: str) -> None:
        for key in keys:
            self.data.pop(key, None)


class TestIsAnalysisFinished(unittest.TestCase):
    def _make_analysis(self, *, age: datetime.timedelta) -> dict[str, Any]:
        return {"id": "analysis-id", "created_at": datetime.datetime.now() - age}

    def test_old_analysis_without_pending_tasks_is_finished(self) -> None:
        self.assertTrue(is_analysis_finished(self._make_analysis(age=datetime.timedelta(hours=1)), {}))

    def test_old_analysis_missing_from_num_pending_tasks_is_finished(self) -> None:
        # Analyses missing from num_pending_tasks have no pending tasks - e.g. an orphaned analysis
        # whose task was never registered, or one whose tasks are all long gone.
        self.assertTrue(
            is_analysis_finished(self._make_analysis(age=datetime.timedelta(hours=1)), {"other-analysis": 3})
        )

    def test_analysis_with_pending_tasks_is_not_finished(self) -> None:
        self.assertFalse(is_analysis_finished(self._make_analysis(age=datetime.timedelta(hours=1)), {"analysis-id": 1}))

    def test_fresh_analysis_without_tasks_is_not_finished(self) -> None:
        # For a brief period after creation, a new analysis has no Karton tasks yet (between
        # db.create_analysis() and producer.send_task() in the create_tasks() loop in producer.py),
        # so it must not be mistaken for a finished one.
        self.assertFalse(is_analysis_finished(self._make_analysis(age=datetime.timedelta(minutes=1)), {}))

    def test_analysis_exactly_min_age_is_finished(self) -> None:
        analysis = {
            "id": "analysis-id",
            "created_at": datetime.datetime.now() - MIN_ANALYSIS_AGE_TO_BE_CONSIDERED_FINISHED,
        }
        self.assertTrue(is_analysis_finished(analysis, {}))


class TestAnalysisFinishedTime(unittest.TestCase):
    def test_set_get_delete_roundtrip(self) -> None:
        redis = FakeRedis()
        analysis_id = "some-analysis-id"
        finished_at = datetime.datetime.now()

        self.assertIsNone(get_analysis_finished_time(redis, analysis_id))  # type: ignore[arg-type]

        set_analysis_finished_time(
            redis,  # type: ignore[arg-type]
            analysis_id,
            finished_at,
            ttl_seconds=60 * 60 * 24,
        )
        self.assertEqual(get_analysis_finished_time(redis, analysis_id), finished_at)  # type: ignore[arg-type]
        self.assertIn(ARTEMIS_ANALYSIS_FINISHED_AT_KEY_PREFIX + analysis_id, redis.data)

        delete_analysis_finished_time(redis, analysis_id)  # type: ignore[arg-type]
        self.assertIsNone(get_analysis_finished_time(redis, analysis_id))  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
