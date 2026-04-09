import os
from typing import Any, Dict, List, Tuple

from flask import Flask, Response, jsonify, request
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import (  # type: ignore[attr-defined]
    Session,
    declarative_base,
    sessionmaker,
)

app = Flask(__name__)

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://postgres:postgres@orm-injection-test-postgres:5432/postgres"
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class User(Base):  # type: ignore[valid-type,misc]
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100))
    password = Column(String(200))
    email = Column(String(200))
    is_admin = Column(Integer, default=0)


ALLOWED_ORM_LOOKUPS = {
    "exact": lambda col: col.__eq__,
    "iexact": lambda col: lambda v: col.ilike(v),
    "contains": lambda col: lambda v: col.contains(v),
    "icontains": lambda col: lambda v: col.ilike(f"%{v}%"),
    "startswith": lambda col: lambda v: col.startswith(v),
    "istartswith": lambda col: lambda v: col.ilike(f"{v}%"),
    "endswith": lambda col: lambda v: col.endswith(v),
    "iendswith": lambda col: lambda v: col.ilike(f"%{v}"),
    "gt": lambda col: col.__gt__,
    "gte": lambda col: col.__ge__,
    "lt": lambda col: col.__lt__,
    "lte": lambda col: col.__le__,
    "regex": lambda col: lambda v: col.regexp_match(v),
    "iregex": lambda col: lambda v: col.regexp_match(v, "i"),
}


def parse_orm_params(params: Dict[str, str]) -> List[Any]:
    """Parse Django-style ORM lookup parameters into SQLAlchemy filters.

    Simulates Django's Model.objects.filter(**request.GET) behavior.
    """
    filters = []
    columns = {c.name: c for c in User.__table__.columns}

    for key, value in params.items():
        # Try to split on the last __ to get field and lookup
        parts = key.rsplit("__", 1)
        if len(parts) == 2:
            field_name, lookup = parts
            if field_name in columns and lookup in ALLOWED_ORM_LOOKUPS:
                col = columns[field_name]
                filter_fn = ALLOWED_ORM_LOOKUPS[lookup](col)  # type: ignore[no-untyped-call]
                filters.append(filter_fn(value))
                continue

        # No ORM suffix or unknown suffix - treat as exact match
        field_name = key
        if field_name in columns:
            col = columns[field_name]
            filters.append(col == value)

    return filters


def init_db() -> None:
    Base.metadata.create_all(engine)
    session = SessionLocal()
    if session.query(User).count() == 0:
        session.add_all(
            [
                User(
                    username="admin",
                    password="pbkdf2_sha256$260000$hash123",
                    email="admin@example.com",
                    is_admin=1,
                ),
                User(
                    username="guest",
                    password="pbkdf2_sha256$260000$hash456",
                    email="guest@example.com",
                    is_admin=0,
                ),
                User(
                    username="john",
                    password="pbkdf2_sha256$260000$hash789",
                    email="john@company.org",
                    is_admin=0,
                ),
            ]
        )
        session.commit()
    session.close()


@app.route("/")
def index() -> str:
    return (
        "<html><body>"
        '<a href="/search?username=admin">Search admin</a> '
        '<a href="/search?username=guest">Search guest</a> '
        '<a href="/safe?name=admin">Safe search</a>'
        "</body></html>"
    )


@app.route("/search")
def search() -> Tuple[Response, int]:
    """Vulnerable endpoint: passes all GET params directly to ORM filter."""
    params = {k: v for k, v in request.args.items()}

    session = SessionLocal()
    query = session.query(User)

    filters = parse_orm_params(params)
    if filters:
        for f in filters:
            query = query.filter(f)

    users = query.all()
    result = [{"id": u.id, "username": u.username} for u in users]
    session.close()

    return jsonify({"count": len(result), "users": result}), 200


@app.route("/safe")
def safe_search() -> Tuple[Response, int]:
    """Safe endpoint: only allows whitelisted parameters."""
    name = request.args.get("name", "")

    session: Session = SessionLocal()
    users = session.query(User).filter(User.username == name).all()
    result = [{"id": u.id, "username": u.username} for u in users]
    session.close()

    return jsonify({"count": len(result), "users": result}), 200


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", debug=False)
