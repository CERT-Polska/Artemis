from pathlib import Path

# This is the output location *inside the container*. The scripts/export_reports
# script is responsible for mounting a host path to a path inside the container.
OUTPUT_LOCATION = Path("./output/autoreporter/")
