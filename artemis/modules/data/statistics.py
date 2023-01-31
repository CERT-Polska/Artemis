import os

STATISTICS = []

for line in open(os.path.join(os.path.dirname(__file__), "bruter_initial_statistics.txt")):
    if line:
        count_str, path = line.strip().split(" ", 1)
        count_int = int(count_str)
        STATISTICS.append(
            {"name": "bruter", "count": count_int, "value": path},
        )
