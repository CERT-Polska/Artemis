import sqlite3
import json
from typing import Any, Dict, Optional, Tuple, Union

from flask import Flask, Response, jsonify, request, send_file

app = Flask(__name__)
DATABASE = "/tmp/test.db"


# Setup DB and dummy data
def init_db() -> None:
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    """
    )
    c.execute("INSERT INTO users (username, password) VALUES ('admin', 'supersecret')")
    c.execute("INSERT INTO users (username, password) VALUES ('guest', 'guest123')")
    conn.commit()
    conn.close()


@app.route("/")
def index() -> Tuple[Response, int]:
    return jsonify({"message": "Test API with SQLi vulnerabilities"}), 200


# Vulnerable to SQLi via POST body
@app.route("/api/login", methods=["POST"])
def login() -> Tuple[Response, int]:
    data: Optional[Dict[str, Any]] = request.get_json()
    username: Optional[str] = data.get("username") if data else None
    password: Optional[str] = data.get("password") if data else None

    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"Executing query: {query}")

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute(query)
    user: Optional[Tuple[Any, ...]] = c.fetchone()
    conn.close()

    if user:
        return jsonify({"message": "Login successful", "user": user[1]}), 200
    else:
        return jsonify({"message": "Login failed"}), 401


# Vulnerable to SQLi via path parameter
@app.route("/api/user/<username>", methods=["GET"])
def get_user(username: str) -> Tuple[Response, int]:
    query = f"SELECT * FROM users WHERE username = '{username}'"
    print(f"Executing query: {query}")

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute(query)
    user: Optional[Tuple[Any, ...]] = c.fetchone()
    conn.close()

    if user:
        return jsonify({"user-id": user[0], "username": user[1]}), 200
    else:
        return jsonify({"message": "User not found"}), 404

@app.route("/api/xss", methods=["GET"])
def xss_test() -> Response:
    payload = request.args.get("payload", "")

    # A standard problem+json response
    problem_details = {
        "type": "about:blank",
        "title": "XSS Test Endpoint",
        "status": 400,
        "detail": f"The provided payload was: {payload}",
        "instance": request.path,
    }

    response = Response(
        json.dumps(problem_details),
        status=400,
        mimetype="application/problem+json; charset=utf-8",
    )
    return response


@app.route("/api/docs", methods=["GET"])
def get_openapi_spec() -> Union[Response, Tuple[Response, int]]:
    try:
        return send_file("openapi.json", mimetype="application/json")
    except FileNotFoundError:
        return jsonify({"error": "OpenAPI spec not found"}), 404


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", debug=False)
