import datetime
from typing import Any, List, Tuple

from pymongo import MongoClient
from sqlalchemy.dialects.postgresql import insert as postgres_upsert
from sqlalchemy.orm.exc import NoResultFound
from tqdm import tqdm

from artemis.config import Config
from artemis.db import DB, Analysis, MigrationLog, ScheduledTask, Session, TaskResult
from artemis.utils import build_logger

logger = build_logger(__name__)


def _list_of_tuples_to_str(lst: List[Tuple[str, Any]]) -> str:
    tmp = {}
    for key, value in lst:
        if isinstance(value, list) and all(len(item) == 2 for item in value):
            tmp[key] = _list_of_tuples_to_str(value)
        else:
            tmp[key] = value
    return DB.dict_to_str(tmp)


def migrate_if_needed() -> None:
    client = MongoClient(Config.Data.LEGACY_MONGODB_CONN_STR)

    session = Session()
    try:
        session.query(MigrationLog).get("initial")
        logger.info("Data already migrated")
        return
    except NoResultFound:
        pass

    with client.start_session() as session:
        logger.info("Migrating analyses...")
        try:
            cursor = client.artemis.analysis.find({})
            for item in tqdm(cursor):
                statement = postgres_upsert(Analysis).values(
                    [
                        {
                            "id": item["_id"],
                            "created_at": datetime.datetime.utcfromtimestamp(item["last_update"]),
                            "target": item["payload"]["data"],
                            "tag": item["payload_persistent"].get("tag", ""),
                            "stopped": item.get("stopped", False),
                            "task": item,
                        }
                    ]
                )
                statement = statement.on_conflict_do_nothing()
                session = Session()
                session.execute(statement)
                session.commit()
        finally:
            cursor.close()

        logger.info("Migrating task results...")
        try:
            cursor = client.artemis.task_results.find({})
            for item in tqdm(cursor):
                statement = postgres_upsert(TaskResult).values(
                    [
                        {
                            "id": item["_id"],
                            "analysis_id": item["root_uid"],
                            "created_at": item["created_at"],
                            "status": item["status"],
                            "tag": item["payload_persistent"].get("tag", ""),
                            "receiver": item["headers"]["receiver"],
                            "target_string": item["target_string"],
                            "status_reason": item["status_reason"],
                            "headers_string": item["headers_string"],
                            "task": item,
                            "result": item["result"],
                        }
                    ]
                )
                statement = statement.on_conflict_do_nothing()
                session = Session()
                session.execute(statement)
                session.commit()
        finally:
            cursor.close()

        logger.info("Migrating scheduled tasks...")
        try:
            cursor = client.artemis.scheduled_tasks.find({})
            for item in tqdm(cursor):
                statement = postgres_upsert(ScheduledTask).values(
                    [
                        {
                            "created_at": item["created_at"],
                            "task_id": item["uid"],
                            "analysis_id": item["analysis_id"],
                            "deduplication_data": _list_of_tuples_to_str(item["deduplication_data"]),
                        }
                    ]
                )
                statement = statement.on_conflict_do_nothing()
                session = Session()
                session.execute(statement)
                session.commit()
        finally:
            cursor.close()

    session = Session()
    session.add(MigrationLog("initial"))
    session.commit()
