"""
Minimal Flask app with intentional CORS misconfigurations for testing.

Two endpoints:
  /vulnerable   — reflects the Origin header and sets ACAC: true (exploitable)
  /safe         — returns a fixed ACAO without credentials (not exploitable)
"""

from flask import Flask, Response, request

app = Flask(__name__)


@app.route("/vulnerable")
def vulnerable() -> Response:
    """Reflects any Origin with credentials — a real CORS misconfiguration."""
    origin = request.headers.get("Origin", "")
    resp = Response("sensitive data", status=200, content_type="text/plain")
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


@app.route("/safe")
def safe() -> Response:
    """Fixed wildcard origin, no credentials — safe configuration."""
    resp = Response("public data", status=200, content_type="text/plain")
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


@app.route("/")
def index() -> Response:
    """No CORS headers at all — safe (default deny)."""
    return Response("hello", status=200, content_type="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
