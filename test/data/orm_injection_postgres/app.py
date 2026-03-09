import os
import time

from flask import Flask, request
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg2://postgres:postgres@orm-injection-test-postgres:5432/artemis",
)

engine = create_engine(DATABASE_URL, future=True)


def initialize_db(max_attempts: int = 40, sleep_seconds: int = 1) -> None:
    for _ in range(max_attempts):
        try:
            with engine.connect() as connection:
                connection.execute(
                    text(
                        "CREATE TABLE IF NOT EXISTS users ("
                        "id SERIAL PRIMARY KEY, "
                        "name VARCHAR(255) NOT NULL"
                        ")"
                    )
                )
                connection.execute(text("TRUNCATE TABLE users RESTART IDENTITY"))
                connection.execute(text("INSERT INTO users (name) VALUES ('alice'), ('bob')"))
                connection.commit()
            return
        except Exception:
            time.sleep(sleep_seconds)

    raise RuntimeError("Database initialization failed")


app = Flask(__name__)


@app.route("/")
def index() -> str:
    return (
        "<html><body>"
        '<a href="/orm_injection?id=1">orm_injection</a>'
        '<a href="/headers_vuln">headers_vuln</a>'
        "</body></html>"
    )


@app.route("/orm_injection")
def orm_injection() -> tuple[str, int] | str:
    user_input = request.args.get("id", "1")
    query = text(f"SELECT id, name FROM users WHERE id = {user_input}")

    try:
        with engine.connect() as connection:
            rows = connection.execute(query).fetchall()
        return ",".join([str(row[0]) for row in rows])
    except SQLAlchemyError as exception:
        error_name = f"{exception.__class__.__module__}.{exception.__class__.__name__}"
        return f"{error_name}: {exception}", 500


@app.route("/headers_vuln")
def headers_vuln() -> tuple[str, int] | str:
    user_agent = request.headers.get("User-Agent", "alice")

    query = text(f"SELECT id, name FROM users WHERE name = '{user_agent}'")

    try:
        with engine.connect() as connection:
            rows = connection.execute(query).fetchall()
        return ",".join([str(row[0]) for row in rows])
    except SQLAlchemyError as exception:
        error_name = f"{exception.__class__.__module__}.{exception.__class__.__name__}"
        return f"{error_name}: {exception}", 500


if __name__ == "__main__":
    initialize_db()
    app.run(host="0.0.0.0", port=80)

