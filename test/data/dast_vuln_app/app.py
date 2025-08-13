import os
from typing import Tuple

from flask import Flask, Response, jsonify, request

app = Flask(__name__)


@app.route("/")
def index() -> Tuple[Response, int]:
    filename = request.args.get("filename", "")
    if filename:
        return jsonify({"message": open(os.path.join("/tmp", filename), "r").read()}), 200
    return jsonify({"message": "Testing DAST templates"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=False)
