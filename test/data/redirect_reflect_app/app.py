from flask import Flask, Response, redirect, request
from werkzeug.wrappers import Response as WerkzeugResponse

app = Flask(__name__)


@app.route("/")
def index() -> WerkzeugResponse:
    qs = request.query_string.decode("utf-8")
    target = "/search" + ("?" + qs if qs else "")
    return redirect(target, code=302)


@app.route("/search")
def search() -> Response:
    parts = ["<html><body>"]
    for value in request.args.values():
        parts.append(value)
    parts.append("</body></html>")
    return Response(" ".join(parts), status=200, content_type="text/html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=False)
