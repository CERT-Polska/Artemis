from sqlalchemy import update
import time

from artemis import utils
from artemis.db import Analysis, DB, TaskPriority

from artemis.karton_utils import change_priority_for_analyses

db = DB()
LOGGER = utils.build_logger(__name__)
DELAY_BETWEEN_REPRIORITIZATION__SECONDS = 15


def reprioritize_analyses() -> None:
    analyses_to_reprioritize = db.get_analyses_to_reprioritize()
    analyses_priority_to_ids = {priority.value: [] for priority in TaskPriority}
    for analysis in analyses_to_reprioritize:
        analyses_priority_to_ids[analysis.get("desired_priority").value].append(analysis.get("id"))
    
    for priority, analyses_ids in analyses_priority_to_ids.items():
        change_priority_for_analyses(analyses_ids, priority)
    
        with db.session() as session:
            session.execute(
                update(Analysis)
                .where(Analysis.id.in_(analyses_ids))
                .values(priority=Analysis.desired_priority)
            )
            session.commit()


def main() -> None:
    LOGGER.info("Trying to reprioritize analyses...")
    reprioritize_analyses()


if __name__ == "__main__":
    while True:
        try:
            main()
        except Exception:
            LOGGER.exception("Error during reprioritizing analyses, will retry")
        time.sleep(DELAY_BETWEEN_REPRIORITIZATION__SECONDS)