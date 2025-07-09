import os
import subprocess
import json
from typing import List, Any
import logging


def run_tech_detection(urls: List[str], logger: logging.Logger) -> Any:
    """
    Run technology detection on a list of URLs using Wappalyzer.
    """
    wappalyzer_path = os.path.join(os.path.dirname(__file__), "modules", "utils", "wappalyzer")
    main_go_path = os.path.join(wappalyzer_path, "main.go")
    if not os.path.exists(main_go_path):
        logger.error(f"Wappalyzer main.go not found at {main_go_path}")
        return {url: [] for url in urls}

    try:
        # Update the Wappalyzer package once
        subprocess.run(["go", "get", "-u", "./..."], cwd=wappalyzer_path, check=True, capture_output=True)

        temp_file_name = "/tmp/temp_urls.txt"
        with open(temp_file_name, "w") as f:
            for url in urls:
                f.write(url + "\n")

        wappalyzer_output = subprocess.check_output(
            ["go", "run", main_go_path, temp_file_name], cwd=wappalyzer_path
        )
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"Error running technology detection: {e}")
    finally:
        if os.path.exists(temp_file_name):
            os.remove(temp_file_name)
        # The output is a mapping from URL to a list of detected app names
        return json.loads(wappalyzer_output)
