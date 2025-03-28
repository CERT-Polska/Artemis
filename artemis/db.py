import copy
import dataclasses
import datetime
import enum
import functools
import hashlib
import json
import os
import shutil
from enum import Enum
from typing import Any, Dict, Generator, List, Optional, Type

from karton.core import Task
from pydantic import BaseModel
from sqlalchemy import (  # type: ignore
    JSON,
    Boolean,
    Column,
    Computed,
    DateTime,
    Index,
    Integer,
    String,
    create_engine,
)
from sqlalchemy.dialects.postgresql import TSVECTOR
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.orm import declarative_base, sessionmaker  # type: ignore
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql.expression import select, text
from sqlalchemy.types import TypeDecorator

from artemis.binds import TaskStatus
from artemis.config import Config
from artemis.json_utils import JSONEncoderAdditionalTypes
from artemis.reporting.base.language import Language
from artemis.task_utils import get_task_target
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
    disabled_modules = Column(String, index=True)  # comma-separated

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
    logs = Column(String)
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


class ReportGenerationTaskStatus(str, enum.Enum):
    PENDING = "pending"
    DONE = "done"
    FAILED = "failed"


class ReportGenerationTask(Base):  # type: ignore
    __tablename__ = "report_generation_task"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, server_default=text("NOW()"))
    comment = Column(String, index=True)

    status = Column(String, index=True)
    tag = Column(String, nullable=True)
    language = Column(String)
    skip_previously_exported = Column(Boolean)
    skip_hooks = Column(Boolean)
    skip_suspicious_reports = Column(Boolean)
    custom_template_arguments = Column(JSON)
    output_location = Column(String, nullable=True)
    error = Column(String, nullable=True)
    alerts = Column(JSON, nullable=True)


class Tag(Base):  # type: ignore
    __tablename__ = "tag"

    id = Column(Integer, primary_key=True)
    tag_name = Column(String, index=True, unique=True)
    created_at = Column(DateTime, server_default=text("NOW()"))


@dataclasses.dataclass
class PaginatedResults:
    records_count_total: int
    records_count_filtered: int
    data: List[Dict[str, Any]]


class TagArchiveRequest(Base):  # type: ignore
    __tablename__ = "tag_archive_request"
    id = Column(Integer, primary_key=True)
    tag = Column(String, index=True)


class DB:
    def __init__(self) -> None:
        self.logger = build_logger(__name__)

        self._engine = create_engine(
            Config.Data.POSTGRES_CONN_STR, json_serializer=functools.partial(json.dumps, cls=JSONEncoderAdditionalTypes)
        )
        self.session = sessionmaker(bind=self._engine)

    def list_analysis(self) -> List[Dict[str, Any]]:
        with self.session() as session:
            return [self._strip_internal_db_info(item.__dict__) for item in session.query(Analysis).all()]

    def mark_analysis_as_stopped(self, analysis_id: str) -> None:
        with self.session() as session:
            analysis = session.query(Analysis).get(analysis_id)
            analysis.stopped = True
            session.add(analysis)
            session.commit()

    def save_task_logs(self, task_id: str, logs: bytes) -> None:
        with self.session() as session:
            try:
                task = session.query(TaskResult).get(task_id)
            except NoResultFound:
                return

            task.logs = logs.decode("utf-8", errors="replace")
            session.add(task)
            session.commit()

    def create_analysis(self, analysis: Task) -> None:
        analysis_dict = self.task_to_dict(analysis)

        analysis = Analysis(
            id=analysis.root_uid,
            target=analysis_dict["payload"]["data"],
            tag=analysis_dict["payload_persistent"].get("tag", None),
            stopped=False,
            disabled_modules=analysis_dict["payload_persistent"]["disabled_modules"],
        )
        with self.session() as session:
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

        del to_save["task"]["status"]  # at the moment of saving it's "started", which will be misleading

        if isinstance(data, BaseModel):
            to_save["result"] = data.dict()
        elif isinstance(data, Exception):
            to_save["result"] = str(data)
        else:
            to_save["result"] = data

        statement = postgres_insert(TaskResult).values([copy.copy(to_save)])
        del to_save["id"]
        statement = statement.on_conflict_do_update(index_elements=[TaskResult.id], set_=to_save)

        with self.session() as session:
            session.execute(statement)
            session.commit()

    def get_analysis_by_id(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        try:
            with self.session() as session:
                item = session.query(Analysis).get(analysis_id)

                if item:
                    return self._strip_internal_db_info(item.__dict__)
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
            (
                getattr(Analysis, ordering_rule.column_name)
                if ordering_rule.ascending
                else getattr(Analysis, ordering_rule.column_name).desc()
            )
            for ordering_rule in ordering
        ]

        with self.session() as session:
            records_count_total = session.query(Analysis).count()

            query = session.query(Analysis)

            if search_query:
                query = query.filter(Analysis.fulltext.match(self._to_postgresql_query(search_query)))  # type: ignore

            records_count_filtered: int = query.count()
            results_page = [
                self._strip_internal_db_info(item.__dict__)
                for item in query.order_by(*ordering_postgresql).slice(start, start + length)
            ]
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
        *,
        search_query: Optional[str] = None,
        analysis_id: Optional[str] = None,
        task_filter: Optional[TaskFilter] = None,
    ) -> PaginatedResults:
        ordering_postgresql = [
            (
                getattr(TaskResult, ordering_rule.column_name)
                if ordering_rule.ascending
                else getattr(TaskResult, ordering_rule.column_name).desc()
            )
            for ordering_rule in ordering
        ]

        with self.session() as session:
            records_count_total = session.query(TaskResult).count()

            query = session.query(TaskResult)

            if search_query:
                query = query.filter(TaskResult.fulltext.match(self._to_postgresql_query(search_query)))  # type: ignore

            if analysis_id:
                query = query.filter(TaskResult.analysis_id == analysis_id)

            if task_filter:
                for key, value in task_filter.as_dict().items():
                    query = query.filter(getattr(TaskResult, key) == value)

            records_count_filtered = query.count()
            results_page = [
                self._strip_internal_db_info(item.__dict__)
                for item in query.order_by(*ordering_postgresql).slice(start, start + length)
            ]
            return PaginatedResults(
                records_count_total=records_count_total,
                records_count_filtered=records_count_filtered,
                data=results_page,
            )

    def get_task_by_id(self, task_id: str) -> Optional[Dict[str, Any]]:
        try:
            with self.session() as session:
                item = session.query(TaskResult).get(task_id)

                if item:
                    return self._strip_internal_db_info(item.__dict__)
                else:
                    return None
        except NoResultFound:
            return None

    def delete_analysis(self, id: str) -> None:
        with self.session() as session:
            analysis = session.query(Analysis).get(id)
            session.delete(analysis)
            session.commit()

    def delete_task_result(self, id: str) -> None:
        with self.session() as session:
            task_result = session.query(TaskResult).get(id)
            session.delete(task_result)
            session.commit()

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

        statement = postgres_insert(ScheduledTask).values([created_task])

        statement = statement.on_conflict_do_nothing()
        with self.session() as session:
            result = session.execute(statement)
            session.commit()
            return bool(result.rowcount)

    def get_task_results_since(
        self, time_from: datetime.datetime, tag: Optional[str] = None, batch_size: int = 100
    ) -> Generator[Dict[str, Any], None, None]:
        query = select(TaskResult).filter(TaskResult.created_at >= time_from)  # type: ignore
        if tag:
            query = query.filter(TaskResult.tag == tag)
        return self._iter_results(query, batch_size)

    def get_oldest_task_results_with_tag(
        self, tag: str, max_length: int, batch_size: int = 100
    ) -> List[Dict[str, Any]]:
        query = select(TaskResult).filter(TaskResult.tag == tag).order_by(TaskResult.created_at)  # type: ignore
        result = []
        for i, item in enumerate(self._iter_results(query, batch_size)):
            if i >= max_length:
                break
            result.append(self._strip_internal_db_info(dict(item)))
        return result

    def get_oldest_task_results_before(
        self, time_to: datetime.datetime, max_length: int, batch_size: int = 100
    ) -> List[Dict[str, Any]]:
        query = select(TaskResult).filter(TaskResult.created_at <= time_to).order_by(TaskResult.created_at)  # type: ignore
        result = []
        for i, item in enumerate(self._iter_results(query, batch_size)):
            if i >= max_length:
                break
            result.append(self._strip_internal_db_info(dict(item)))
        return result

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

    def take_single_report_generation_task(self) -> Optional[ReportGenerationTask]:
        with self.session() as session:
            return (  # type: ignore
                session.query(ReportGenerationTask)
                .filter(ReportGenerationTask.status == ReportGenerationTaskStatus.PENDING.value)
                .first()
            )

    def save_report_generation_task_results(
        self,
        task: ReportGenerationTask,
        status: ReportGenerationTaskStatus,
        output_location: Optional[str] = None,
        error: Optional[str] = None,
        alerts: Optional[List[str]] = None,
    ) -> None:
        with self.session() as session:
            task.status = status.value
            if output_location:
                task.output_location = output_location
            if error:
                task.error = error
            if alerts:
                task.alerts = alerts
            session.add(task)
            session.commit()

    def create_report_generation_task(
        self,
        tag: Optional[str],
        comment: Optional[str],
        language: Language,
        skip_previously_exported: bool,
        skip_hooks: bool = False,
        skip_suspicious_reports: bool = False,
        custom_template_arguments: Dict[str, Any] = {},
    ) -> None:
        with self.session() as session:
            task = ReportGenerationTask(
                tag=tag,
                comment=comment,
                language=language.value,
                skip_previously_exported=skip_previously_exported,
                status=ReportGenerationTaskStatus.PENDING,
                skip_hooks=skip_hooks,
                skip_suspicious_reports=skip_suspicious_reports,
                custom_template_arguments=custom_template_arguments,
            )
            session.add(task)
            session.commit()

    def get_report_generation_task(self, id: int) -> Optional[ReportGenerationTask]:
        with self.session() as session:
            return session.query(ReportGenerationTask).filter(ReportGenerationTask.id == id).first()  # type: ignore

    def list_report_generation_tasks(self, tag_prefix: Optional[str] = None) -> List[ReportGenerationTask]:
        with self.session() as session:
            query = session.query(ReportGenerationTask)
            if tag_prefix:
                if "%" in tag_prefix:
                    raise NotImplementedError()

                query = query.filter(ReportGenerationTask.tag.like(tag_prefix + "%"))
            return list(query.order_by(ReportGenerationTask.created_at.desc()))

    def delete_report_generation_task(self, id: int) -> None:
        with self.session() as session:
            task = session.query(ReportGenerationTask).get(id)
            if task.output_location:
                output_location = "/opt/" + task.output_location
                if os.path.exists(output_location):
                    # Make sure we don't remove too much
                    assert os.path.normpath(output_location).startswith("/opt/output/autoreporter/")
                    shutil.rmtree(output_location)
            session.delete(task)
            session.commit()

    def _iter_results(self, query: Any, batch_size: int) -> Generator[Dict[str, Any], None, None]:
        with self._engine.connect() as conn:
            with conn.execution_options(stream_results=True, max_row_buffer=batch_size).execute(query) as result:
                for item in result:
                    yield item._mapping

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
        ).replace("\x00", " ")

    def _to_postgresql_query(self, query: str) -> str:
        """Converts a space-separated query (e.g. directory_index wp-content) to a MongoDB query
        that requires all words to be present (in that case it would be "directory_index" AND "wp-content").
        """

        query = query.replace("\\", " ")  # just in case
        query = query.replace('"', " ")  # just in case
        return " & ".join([f'"{item}"' for item in query.split(" ") if item])

    def _strip_internal_db_info(self, d: Dict[str, Any]) -> Dict[str, Any]:
        if "_sa_instance_state" in d:
            del d["_sa_instance_state"]
        if "fulltext" in d:
            del d["fulltext"]
        if "headers_string" in d:
            del d["headers_string"]
        return d

    def save_tag(self, tag_name: str | None) -> None:
        if tag_name is not None:
            statement = postgres_insert(Tag).values(tag_name=tag_name)
            statement = statement.on_conflict_do_nothing(index_elements=[Tag.tag_name])
            with self.session() as session:
                session.execute(statement)
                session.commit()

    def get_tags(self) -> List[Type[Tag]] | Any:
        with self.session() as session:
            return session.query(Tag).all()

    def list_tag_archive_requests(self) -> List[Dict[str, Any]]:
        with self.session() as session:
            return [self._strip_internal_db_info(item.__dict__) for item in session.query(TagArchiveRequest).all()]

    def create_tag_archive_request(self, tag: str) -> None:
        tag_archive_request = TagArchiveRequest(tag=tag)
        with self.session() as session:
            session.add(tag_archive_request)
            session.commit()

    def delete_tag_archive_request(self, tag: str) -> None:
        with self.session() as session:
            tag_archive_requests = session.query(TagArchiveRequest).filter(TagArchiveRequest.tag == tag)
            for tag_archive_request in tag_archive_requests:
                session.delete(tag_archive_request)
                session.commit()
