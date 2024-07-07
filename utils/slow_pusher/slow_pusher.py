import random
import time

import requests
import typer


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

    To use the script, Artemis API needs to be enabled.
    """
    with open(targets_file_name, "r") as f:
        all_targets = set([line.strip() for line in f])

    while True:
        num_queued_tasks = int(
            requests.get(
                artemis_url + "api/num-queued-tasks",
                headers={"X-API-Token": api_token},
            ).content
        )
        num_queued_tasks_target_enumeration_kartons = int(
            requests.get(
                artemis_url + "api/num-queued-tasks?karton_names=subdomain_enumeration&karton_names=port_scanner",
                headers={"X-API-Token": api_token},
            ).content
        )

        existing_targets = set(
            [
                item["target"]
                for item in requests.get(
                    artemis_url + "api/analyses",
                    headers={"X-API-Token": api_token},
                ).json()
            ]
        ) & set(all_targets)

        print(f"Num queued tasks: {num_queued_tasks}")
        print(f"Num queued tasks for target enumeration kartons: {num_queued_tasks_target_enumeration_kartons}")
        print(
            f"Targets queued: {len(existing_targets)} of {len(all_targets)} ({100.0 * len(existing_targets) / len(all_targets):.2f}%)"
        )

        if (
            num_queued_tasks < max_queued_tasks
            and num_queued_tasks_target_enumeration_kartons < max_queued_tasks_target_enumeration_kartons
        ):
            potential_targets = list(all_targets - existing_targets)
            random.shuffle(potential_targets)
            targets = potential_targets[:batch_size]

            print(f"Adding {', '.join(targets)}")
            response = requests.post(
                artemis_url + "api/add",
                json={"targets": targets, "tag": tag, "redirect": False},
                headers={"X-API-Token": api_token},
            )

            if response.status_code == 200:
                print(f"Added {', '.join(targets)} successfully")
            else:
                print(f"Failed to add {', '.join(targets)}, code={response.status_code}, result={response.json()}")
        else:
            print(
                f"Sleeping - need <{max_queued_tasks} (all kartons) and <{max_queued_tasks_target_enumeration_kartons} (target enumeration kartons) to continue"
            )
        time.sleep(time_between_attempts_seconds)


if __name__ == "__main__":
    typer.run(main)
