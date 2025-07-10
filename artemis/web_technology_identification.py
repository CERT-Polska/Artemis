import json
import logging
import os
import subprocess
import tempfile
from typing import Any, List


def run_tech_detection(urls: List[str], logger: logging.Logger) -> Any:
    """
    Run technology detection on a list of URLs using Wappalyzer.
    """
    wappalyzer_path = os.path.join(os.path.dirname(__file__), "modules", "utils", "wappalyzer")
    main_go_path = os.path.join(wappalyzer_path, "main.go")
    if not os.path.exists(main_go_path):
        raise FileNotFoundError(f"Wappalyzer main.go not found at {main_go_path}")

    try:
        # Update the Wappalyzer package once
        subprocess.run(["go", "get", "-u", "./..."], cwd=wappalyzer_path, check=True, capture_output=True)

        with tempfile.NamedTemporaryFile(mode="w") as temp_file:
            for url in urls:
                temp_file.write(url + "\n")
            temp_file.flush()
            os.fsync(temp_file.fileno())

            wappalyzer_output = subprocess.check_output(
                ["go", "run", main_go_path, temp_file.name], cwd=wappalyzer_path
            )

        return json.loads(wappalyzer_output)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        logger.error(f"Error running technology detection: {e}")
        return {url: [] for url in urls}
