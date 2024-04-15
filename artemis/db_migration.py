import datetime
import hashlib
import threading
import time
from typing import Any, List, Tuple

from pymongo import ASCENDING, MongoClient
from sqlalchemy.dialects.postgresql import insert as postgres_upsert
from tqdm import tqdm

from artemis.config import Config
from artemis.db import DB, Analysis, ScheduledTask, TaskResult
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


def _single_migration_iteration() -> None:
    db = DB()
    client = MongoClient(Config.Data.LEGACY_MONGODB_CONN_STR)
    with client.start_session() as mongo_session:
        if client.artemis.analysis.count_documents({"migrated": {"$exists": False}}):
            logger.info("Migrating analyses...")
            try:
                cursor = client.artemis.analysis.find({"migrated": {"$exists": False}}, session=mongo_session)
                for item in tqdm(cursor):
                    statement = postgres_upsert(Analysis).values(
                        [
                            {
                                "id": item["_id"],
                                "created_at": datetime.datetime.utcfromtimestamp(item["last_update"]),
                                "target": item["payload"]["data"],
                                "tag": item["payload_persistent"].get("tag", ""),
                                "stopped": item.get("stopped", False),
                            }
                        ]
                    )
                    statement = statement.on_conflict_do_nothing()
                    session = db.session()
                    session.execute(statement)
                    session.commit()
                    client.artemis.analysis.update_one({"_id": item["_id"]}, {"$set": {"migrated": True}})
            finally:
                cursor.close()

        if client.artemis.task_results.count_documents({"migrated": {"$exists": False}}):
            logger.info("Migrating task results...")
            try:
                cursor = client.artemis.task_results.find({"migrated": {"$exists": False}}, session=mongo_session)
                for item in tqdm(cursor):
                    statement = postgres_upsert(TaskResult).values(
                        [
                            {
                                "id": item["_id"],
                                "analysis_id": item["root_uid"],
                                "created_at": item.get("created_at", datetime.datetime.now()),
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
                    session = db.session()
                    session.execute(statement)
                    session.commit()
                    client.artemis.task_results.update_one({"_id": item["_id"]}, {"$set": {"migrated": True}})
            finally:
                cursor.close()

        if client.artemis.scheduled_tasks.count_documents({"migrated": {"$exists": False}}):
            logger.info("Migrating scheduled tasks...")
            try:
                cursor = client.artemis.scheduled_tasks.find({"migrated": {"$exists": False}}, session=mongo_session)
                for item in tqdm(cursor):
                    statement = postgres_upsert(ScheduledTask).values(
                        [
                            {
                                "created_at": item["created_at"],
                                "task_id": item["uid"],
                                "analysis_id": item["analysis_id"],
                                "deduplication_data": hashlib.sha256(
                                    _list_of_tuples_to_str(item["deduplication_data"]).encode("utf-8")
                                ).hexdigest(),
                                "deduplication_data_original": _list_of_tuples_to_str(
                                    item["deduplication_data"]
                                ).replace("\x00", ""),
                            }
                        ]
                    )
                    statement = statement.on_conflict_do_nothing()
                    session = db.session()
                    session.execute(statement)
                    session.commit()
                    client.artemis.scheduled_tasks.update_one({"_id": item["_id"]}, {"$set": {"migrated": True}})
            finally:
                cursor.close()


def migrate_and_start_thread() -> None:
    if not Config.Data.LEGACY_MONGODB_CONN_STR:
        return

    client = MongoClient(Config.Data.LEGACY_MONGODB_CONN_STR)
    client.artemis.task_results.create_index([("migrated", ASCENDING)])
    client.artemis.analysis.create_index([("migrated", ASCENDING)])
    client.artemis.scheduled_tasks.create_index([("migrated", ASCENDING)])

    _single_migration_iteration()

    def migration_thread_body() -> None:
        while True:
            time.sleep(20)
            _single_migration_iteration()

    migration_thread = threading.Thread(target=migration_thread_body)
    migration_thread.daemon = True
    migration_thread.start()
