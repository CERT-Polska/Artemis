import logging
import random
import time

import requests
import typer

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)
HANDLER = logging.StreamHandler()
HANDLER.setLevel(logging.INFO)
LOGGER.addHandler(HANDLER)


def main(
    tag: str,
    targets_file_name: str,
    api_token: str,
    max_queued_tasks: int = 50_000,
    max_queued_tasks_target_enumeration_kartons: int = 5000,
    time_between_attempts_seconds: int = 300,
    batch_size: int = 10,
    artemis_url: str = "http://127.0.0.1:5000/",
) -> None:
    """
    Takes target list from `targets_file_name` and adds them to Artemis in batches
    of `batch_size`.

    If there are more than `max_queued_tasks` queued tasks in total (or
    `max_queued_tasks_target_enumeration_kartons` for kartons that create a large number of
    downstream tasks, such as `port_scanner` or `subdomain_enumeration`), this tool will
    sleep so that Artemis is not overlodaed.

    To use the script, Artemis API needs to be enabled. To do that, provide the API_TOKEN
    variable in .env.
    """
    with open(targets_file_name, "r") as f:
        all_targets = set([line.strip() for line in f])

    session = requests.Session()
    session.headers = {"X-API-Token": api_token}

    while True:
        num_queued_tasks = int(
            session.get(
                artemis_url + "api/num-queued-tasks",
            ).content
        )
        num_queued_tasks_target_enumeration_kartons = int(
            session.get(
                artemis_url + "api/num-queued-tasks",
                json=["subdomain_enumeration", "port_scanner"],
            ).content
        )

        existing_targets = set(
            [
                item["target"]
                for item in session.get(
                    artemis_url + "api/analyses",
                ).json()
            ]
        ) & set(all_targets)

        LOGGER.info(f"Num queued tasks: {num_queued_tasks}")
        LOGGER.info(f"Num queued tasks for target enumeration kartons: {num_queued_tasks_target_enumeration_kartons}")
        LOGGER.info(
            f"Targets queued: {len(existing_targets)} of {len(all_targets)} ({100.0 * len(existing_targets) / len(all_targets):.2f}%)"
        )

        if (
            num_queued_tasks < max_queued_tasks
            and num_queued_tasks_target_enumeration_kartons < max_queued_tasks_target_enumeration_kartons
        ):
            potential_targets = list(all_targets - existing_targets)
            random.shuffle(potential_targets)
            targets = potential_targets[:batch_size]

            LOGGER.info(f"Adding {', '.join(targets)}")
            response = session.post(
                artemis_url + "api/add",
                json={"targets": targets, "tag": tag, "redirect": False},
            )

            if response.status_code == 200:
                LOGGER.info(f"Added {', '.join(targets)} successfully")
            else:
                LOGGER.info(
                    f"Failed to add {', '.join(targets)}, code={response.status_code}, result={response.json()}"
                )
        else:
            LOGGER.info(
                f"Sleeping - need <{max_queued_tasks} (all kartons) and <{max_queued_tasks_target_enumeration_kartons} (target enumeration kartons) to continue"
            )
        time.sleep(time_between_attempts_seconds)


if __name__ == "__main__":
    typer.run(main)
