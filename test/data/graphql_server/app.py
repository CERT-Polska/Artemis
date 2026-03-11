"""
Test GraphQL server for artemis/modules/graphql_scanner tests.
Exposes endpoints to cover all scanner checks:

  POST /graphql           — introspection enabled, field suggestions enabled
  GET  /graphql           — returns GraphiQL HTML (debug interface)
"""
from flask import Flask, jsonify, request

app = Flask(__name__)

FULL_SCHEMA = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "types": [
                {"name": "Query", "kind": "OBJECT"},
                {"name": "User", "kind": "OBJECT"},
                {"name": "Post", "kind": "OBJECT"},
                {"name": "String", "kind": "SCALAR"},
                {"name": "Int", "kind": "SCALAR"},
                {"name": "Boolean", "kind": "SCALAR"},
                {"name": "__Schema", "kind": "OBJECT"},
                {"name": "__Type", "kind": "OBJECT"},
                {"name": "__Field", "kind": "OBJECT"},
                {"name": "__InputValue", "kind": "OBJECT"},
                {"name": "__EnumValue", "kind": "OBJECT"},
                {"name": "__Directive", "kind": "OBJECT"},
                {"name": "__DirectiveLocation", "kind": "ENUM"},
            ],
        }
    }
}


@app.route("/graphql", methods=["GET"])
def graphql_get():
    """Return GraphiQL HTML on GET — simulates a debug interface left in production."""
    return (
        """<!DOCTYPE html>
<html>
<head><title>GraphiQL</title></head>
<body>
<div id="graphiql">Loading GraphiQL...</div>
<script src="/graphiql.min.js"></script>
</body>
</html>""",
        200,
        {"Content-Type": "text/html"},
    )


@app.route("/graphql", methods=["POST"])
def graphql_post():
    """Handle GraphQL queries — introspection enabled, returns field suggestions on bad queries."""
    try:
        body = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"errors": [{"message": "Invalid JSON"}]}), 400

    query = body.get("query", "")

    if "__schema" in query:
        return jsonify(FULL_SCHEMA)

    if "__typenme" in query or "typenme" in query:
        return jsonify(
            {
                "errors": [
                    {
                        "message": 'Cannot query field "__typenme" on type "Query". Did you mean "__typename"?',
                        "locations": [{"line": 1, "column": 3}],
                    }
                ]
            }
        )

    if "__typename" in query:
        return jsonify({"data": {"__typename": "Query"}})

    return jsonify({"errors": [{"message": "Unknown query"}]}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
