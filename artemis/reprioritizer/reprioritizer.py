import time

from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig
from karton.core.inspect import KartonState
from sqlalchemy import update

from artemis import utils
from artemis.db import DB, Analysis, TaskPriority
from artemis.karton_utils import change_priority_for_analyses

db = DB()
LOGGER = utils.build_logger(__name__)
DELAY_BETWEEN_REPRIORITIZATION__SECONDS = 1800


def reprioritize_analyses() -> None:
    analyses_to_reprioritize = db.get_analyses_to_reprioritize()
    if not analyses_to_reprioritize:
        return

    analyses_priority_to_ids: dict[str, list[str]] = {priority.value: [] for priority in TaskPriority}
    for analysis in analyses_to_reprioritize:
        LOGGER.info("Reprioritizing %s", analysis)
        analyses_priority_to_ids[analysis["desired_priority"].value].append(analysis.get("id"))  # type: ignore

    backend = KartonBackend(config=KartonConfig())
    state = KartonState(backend=backend)
    # trigger property, so we load all into memory only once
    state.analyses

    all_analysis_ids: list[str] = []
    for desired_priority, analyses_ids in analyses_priority_to_ids.items():
        change_priority_for_analyses(analyses_ids, state, desired_priority)
        all_analysis_ids.extend(analyses_ids)

    if all_analysis_ids:
        with db.session() as session:
            session.execute(
                update(Analysis).where(Analysis.id.in_(all_analysis_ids)).values(priority=Analysis.desired_priority)  # type: ignore
            )
            session.commit()


def main() -> None:
    LOGGER.info("Trying to reprioritize analyses...")
    reprioritize_analyses()
    LOGGER.info("Reprioritized analyses")


if __name__ == "__main__":
    while True:
        try:
            main()
        except Exception:
            LOGGER.exception("Error during reprioritizing analyses, will retry")
        time.sleep(DELAY_BETWEEN_REPRIORITIZATION__SECONDS)
