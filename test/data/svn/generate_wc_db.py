"""Generates .svn/wc.db (run by scripts/test-unit before `docker compose up`).

wc.db is a SQLite database, so it can't be committed as readable text and has to be generated.
It has to exist before `up`, because `up` creates a missing bind mount source as root-owned, and
then this script (running as the host user) couldn't write to it.
"""

import sqlite3
from pathlib import Path

REPOSITORY_URL = "http://test-service-with-exposed-vcs:80/repo"

wc_db = Path(__file__).parent / ".svn" / "wc.db"
wc_db.parent.mkdir(exist_ok=True)
wc_db.unlink(missing_ok=True)

con = sqlite3.connect(wc_db)
con.execute("create table REPOSITORY (root text)")
con.execute("insert into REPOSITORY values (?)", (REPOSITORY_URL,))
con.commit()
