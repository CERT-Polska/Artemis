import os
from typing import Tuple

from flask import Flask, render_template, render_template_string, request

app = Flask(__name__)


@app.route("/")
def index() -> Tuple[str, int]:
    filename = request.args.get("filename", "")
    if filename:
        return str(open(os.path.join("/tmp", filename), "r").read()), 200
    return render_template("index.html"), 200


@app.route("/ssti")
def ssti() -> Tuple[str, int]:
    template = request.args.get("template", "")
    template = template.replace("<", "&lt;").replace(
        ">", "&gt;"
    )  # Prevent XSS templates from executing as it interferes in writing the tests
    return render_template_string(template), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=False)
