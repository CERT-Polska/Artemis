"""
Minimal mock JSON login panel (simulates apps like Grafana, Portainer).

- GET /login → plain HTML with no form (React-style SPA shell)
- POST /login → JSON API: {user/username + password} → {"message": "Logged in"} or 401
"""
from flask import Flask, jsonify, request

app = Flask(__name__)

ADMIN_USER = "admin"
ADMIN_PASSWORD = "admin"


@app.route("/login", methods=["GET"])
def login_page() -> tuple:
    # No HTML form — behaves like Grafana/Portainer SPA
    return "<html><head><title>Login</title></head><body><div id='root'></div></body></html>", 200


@app.route("/login", methods=["POST"])
def login_api() -> tuple:
    data = request.get_json(silent=True) or {}
    user = data.get("user") or data.get("username", "")
    password = data.get("password", "")

    if user == ADMIN_USER and password == ADMIN_PASSWORD:
        return jsonify({"message": "Logged in"}), 200

    return jsonify({"message": "Invalid username or password"}), 401


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=False)
