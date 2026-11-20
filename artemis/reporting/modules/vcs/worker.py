"""
This should be ran as a sandboxed child process to parse attacker-controlled VCS in reporter.py
"""

import sys
from typing import Optional

from artemis.sandboxing import assert_sandboxed

# Fail closed: refuse to even load (and thus map libsqlite3) outside the sandbox.
assert_sandboxed()

import sqlite3  # noqa: E402


def read_remote_url(db_path: str) -> Optional[str]:
    con = sqlite3.connect(db_path)
    try:
        row = con.execute("select root from REPOSITORY").fetchone()
        remote_url: Optional[str] = None
        if row and isinstance(row[0], str):
            remote_url = row[0]
    finally:
        con.close()
    return remote_url


def main() -> None:
    remote_url = read_remote_url(sys.argv[1])
    if remote_url is not None:
        print(remote_url)


if __name__ == "__main__":
    main()
