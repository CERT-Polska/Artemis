import copy
import dataclasses
import datetime
import functools
import hashlib
import json
from enum import Enum
from typing import Any, Dict, Generator, List, Optional

from karton.core import Task
from pydantic import BaseModel
from sqlalchemy import (  # type: ignore
    JSON,
    Boolean,
    Column,
    Computed,
    DateTime,
    Index,
    String,
    create_engine,
)
from sqlalchemy.dialects.postgresql import TSVECTOR
from sqlalchemy.dialects.postgresql import insert as postgres_upsert
from sqlalchemy.orm import declarative_base, sessionmaker  # type: ignore
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql.expression import select, text
from sqlalchemy.types import TypeDecorator

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.json_utils import JSONEncoderAdditionalTypes
from artemis.utils import build_logger


@dataclasses.dataclass
class ColumnOrdering:
    column_name: str
    ascending: bool


class TaskFilter(str, Enum):
    INTERESTING = "interesting"

    def as_dict(self) -> Dict[str, Any]:
        if self.value == TaskFilter.INTERESTING.value:
            return {"status": "INTERESTING"}
        else:
            assert False


Base = declarative_base()
engine = create_engine(
    Config.Data.POSTGRES_CONN_STR, json_serializer=functools.partial(json.dumps, cls=JSONEncoderAdditionalTypes)
)
Session = sessionmaker(bind=engine)


class TSVector(TypeDecorator):  # type: ignore
    impl = TSVECTOR


class ScheduledTask(Base):  # type: ignore
    __tablename__ = "scheduled_task"
    created_at = Column(DateTime, server_default=text("NOW()"))
    analysis_id = Column(String, primary_key=True)
    # The purpose of this column is to be able to quickly find identical scheduled tasks. Therefore
    # we convert them to a string form (deduplication_data_original, created by the
    # _get_task_deduplication_data method) and store the hash of the string in the indexed
    # deduplication_data column (because PostgreSQL limits the max length of indexed column).
    deduplication_data = Column(String, primary_key=True)
    deduplication_data_original = Column(String)
    task_id = Column(String)


class Analysis(Base):  # type: ignore
    __tablename__ = "analysis"
    id = Column(String, primary_key=True)
    created_at = Column(DateTime, server_default=text("NOW()"))
    target = Column(String, index=True)
    tag = Column(String, index=True)
    stopped = Column(Boolean, index=True)
    task = Column(JSON)

    fulltext = Column(
        TSVector(),
        Computed("to_tsvector('english', COALESCE(tag, '') || ' ' || COALESCE(target, ''))", persisted=True),
    )

    __table_args__ = (Index("analysis_fulltext", fulltext, postgresql_using="gin"),)


class TaskResult(Base):  # type: ignore
    __tablename__ = "task_result"
    id = Column(String, primary_key=True)
    analysis_id = Column(String, index=True)
    created_at = Column(DateTime, server_default=text("NOW()"))
    status = Column(String, index=True)
    tag = Column(String, index=True)
    receiver = Column(String, index=True)
    target_string = Column(String, index=True)
    status_reason = Column(String)
    headers_string = Column(String)
    task = Column(JSON)
    result = Column(JSON)

    fulltext = Column(
        TSVector(),
        Computed(
            "to_tsvector('english', COALESCE(status, '') || ' ' || COALESCE(tag, '') || ' ' || COALESCE(target_string, '') || "
            "' ' || COALESCE(headers_string, '') || ' ' || COALESCE(status_reason, ''))",
            persisted=True,
        ),
    )

    __table_args__ = (Index("task_result_fulltext", fulltext, postgresql_using="gin"),)


Base.metadata.create_all(bind=engine)


@dataclasses.dataclass
class PaginatedResults:
    records_count_total: int
    records_count_filtered: int
    data: List[Dict[str, Any]]


def get_task_target(task: Task) -> str:
    result = None
    if task.headers["type"] == TaskType.NEW:
        result = task.payload.get("data", None)
    elif task.headers["type"] == TaskType.IP:
        result = task.payload.get("ip", None)
    elif task.headers["type"] == TaskType.DOMAIN:
        result = task.payload.get("domain", None)
    elif task.headers["type"] == TaskType.WEBAPP:
        result = task.payload.get("url", None)
    elif task.headers["type"] == TaskType.URL:
        result = task.payload.get("url", None)
    elif task.headers["type"] == TaskType.SERVICE:
        if "host" in task.payload and "port" in task.payload:
            result = task.payload["host"] + ":" + str(task.payload["port"])

    if not result:
        result = task.headers["type"] + ": " + task.uid

    assert isinstance(result, str)
    return result


class DB:
    def __init__(self) -> None:
        self.logger = build_logger(__name__)

    def list_analysis(self) -> List[Dict[str, Any]]:
        with Session() as session:
            return [item.__dict__ for item in session.query(Analysis).all()]

    def mark_analysis_as_stopped(self, analysis_id: str) -> None:
        with Session() as session:
            analysis = session.query(Analysis).get(analysis_id)
            analysis.stopped = True
            session.add(analysis)
            session.commit()

    def create_analysis(self, analysis: Task) -> None:
        analysis_dict = self.task_to_dict(analysis)
        del analysis_dict["status"]
        if "status_reason" in analysis_dict:
            del analysis_dict["status_reason"]

        analysis = Analysis(
            id=analysis.uid,
            target=analysis_dict["payload"]["data"],
            tag=analysis_dict["payload_persistent"].get("tag", None),
            stopped=False,
            task=analysis_dict,
        )
        with Session() as session:
            session.add(analysis)
            session.commit()

    def save_task_result(
        self, task: Task, *, status: TaskStatus, status_reason: Optional[str] = None, data: Optional[Any] = None
    ) -> None:
        to_save = dict(
            task=self.task_to_dict(task),
            id=task.uid,
            analysis_id=task.root_uid,
            status=status,
            tag=task.payload_persistent.get("tag", None),
            receiver=task.headers.get("receiver", None),
            target_string=get_task_target(task),
            status_reason=status_reason,
            # Used to allow searching in the names and values of all existing headers
            headers_string=" ".join([key + " " + value for key, value in task.headers.items()]),
        )
        if isinstance(data, BaseModel):
            to_save["result"] = data.dict()
        elif isinstance(data, Exception):
            to_save["result"] = str(data)
        else:
            to_save["result"] = data

        statement = postgres_upsert(TaskResult).values([copy.copy(to_save)])
        del to_save["id"]
        statement = statement.on_conflict_do_update(index_elements=[TaskResult.id], set_=to_save)

        with Session() as session:
            session.execute(statement)
            session.commit()

    def get_analysis_by_id(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        try:
            with Session() as session:
                item = session.query(Analysis).get(analysis_id)

                if item:
                    return item.__dict__  # type: ignore
                else:
                    return None
        except NoResultFound:
            return None

    def get_paginated_analyses(
        self,
        start: int,
        length: int,
        ordering: List[ColumnOrdering],
        *,
        search_query: Optional[str] = None,
    ) -> PaginatedResults:
        ordering_postgresql = [
            getattr(Analysis, ordering_rule.column_name)
            if ordering_rule.ascending
            else getattr(Analysis, ordering_rule.column_name).desc()
            for ordering_rule in ordering
        ]

        with Session() as session:
            records_count_total = session.query(Analysis).count()

            if search_query:
                query = select(Analysis.c.fulltext.match(self._to_postgresql_query(search_query)))
            else:
                query = session.query(Analysis)

            records_count_filtered: int = query.count()  # type: ignore
            results_page = [item.__dict__ for item in query.order_by(*ordering_postgresql)[start : start + length]]  # type: ignore
            return PaginatedResults(
                records_count_total=records_count_total,
                records_count_filtered=records_count_filtered,
                data=results_page,
            )

    def get_paginated_task_results(
        self,
        start: int,
        length: int,
        ordering: List[ColumnOrdering],
        fields: List[str],
        *,
        search_query: Optional[str] = None,
        analysis_id: Optional[str] = None,
        task_filter: Optional[TaskFilter] = None,
    ) -> PaginatedResults:
        ordering_postgresql = [
            getattr(TaskResult, ordering_rule.column_name)
            if ordering_rule.ascending
            else getattr(TaskResult, ordering_rule.column_name).desc()
            for ordering_rule in ordering
        ]

        with Session() as session:
            records_count_total = session.query(TaskResult).count()

            if search_query:
                query = select(TaskResult.c.fulltext.match(self._to_postgresql_query(search_query)))
            else:
                query = session.query(TaskResult)

            if analysis_id:
                query = query.filter(TaskResult.analysis_id == analysis_id)  # type: ignore

            if task_filter:
                for key, value in task_filter.as_dict().items():
                    query = query.filter(getattr(TaskResult, key) == value)  # type: ignore

            records_count_filtered = query.count()
            results_page = [item.__dict__ for item in query.order_by(*ordering_postgresql)[start : start + length]]  # type: ignore
            return PaginatedResults(
                records_count_total=records_count_total,
                records_count_filtered=records_count_filtered,  # type: ignore
                data=results_page,
            )

    def get_task_by_id(self, task_id: str) -> Optional[Dict[str, Any]]:
        try:
            with Session() as session:
                item = session.query(TaskResult).get(task_id)

                if item:
                    return item.__dict__  # type: ignore
                else:
                    return None
        except NoResultFound:
            return None

    def save_scheduled_task(self, task: Task) -> bool:
        """
        Saves a scheduled task and returns True if it didn't exist in the database.

        The purpose of this method is deduplication - making sure identical tasks aren't run twice.
        """
        created_task = {
            "task_id": task.uid,
            "analysis_id": task.root_uid,
            # PostgreSQL limits the length of string if it's an indexed column
            "deduplication_data": hashlib.sha256(self._get_task_deduplication_data(task).encode("utf-8")).hexdigest(),
            "deduplication_data_original": self._get_task_deduplication_data(task),
        }

        statement = postgres_upsert(ScheduledTask).values([created_task])

        statement = statement.on_conflict_do_nothing()
        with Session() as session:
            result = session.execute(statement)
            session.commit()
            return bool(result.rowcount)

    def get_task_results_since(self, time_from: datetime.datetime) -> Generator[Dict[str, Any], None, None]:
        with Session() as session:
            for item in session.query(TaskResult).filter(TaskResult.created_at >= time_from):
                yield item.__dict__

    def _get_task_deduplication_data(self, task: Task) -> str:
        """
        Represents a task so that two identical tasks with different IDs will have the same representation.

        Instead of dictionaries, strings are used (so that e.g. {"domain": "google.com"} becomes
        domain=google.com to facillitate indexing.
        """

        # We convert the task to dict so that we don't have problems e.g. with enums.
        task_as_dict = self.task_to_dict(task)

        # We treat a task that originates from a different karton than an existing one
        # as an existing one.
        if "origin" in task_as_dict["headers"]:
            del task_as_dict["headers"]["origin"]
        if "receiver" in task_as_dict["headers"]:
            del task_as_dict["headers"]["receiver"]
        if "last_domain" in task_as_dict["payload"]:
            del task_as_dict["payload"]["last_domain"]
        if "created_at" in task_as_dict["payload"]:
            del task_as_dict["payload"]["created_at"]

        return self.dict_to_str(
            {
                "headers": task_as_dict["headers"],
                "payload": task_as_dict["payload"],
                "payload_persistent": task_as_dict["payload_persistent"],
            }
        )

    @staticmethod
    def dict_to_str(d: Dict[str, Any]) -> str:
        result = ""
        # We sort the items so that the same dict will always have the same representation
        # regardless of how are the items ordered internally.
        for key, value in sorted(d.items()):
            if isinstance(value, dict):
                result += f"{key}=({DB.dict_to_str(value)})"
            else:
                result += f"{key}={value}"
        return result

    def task_to_dict(self, task: Task) -> Dict[str, Any]:
        return task.to_dict()

    def _to_postgresql_query(self, query: str) -> str:
        """Converts a space-separated query (e.g. directory_index wp-content) to a MongoDB query
        that requires all words to be present (in that case it would be "directory_index" AND "wp-content").
        """

        query = query.replace("\\", " ")  # just in case
        query = query.replace('"', " ")  # just in case
        return " & ".join([f'"{item}"' for item in query.split(" ") if item])
