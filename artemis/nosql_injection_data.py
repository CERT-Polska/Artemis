from typing import Any

NOSQL_ERROR_MESSAGES: list[str] = [
    # MongoDB server / driver
    "MongoServerError",
    "MongoError",
    "MongoServerSelectionError",
    "MongoInvalidArgumentError",
    "unknown operator: \\$",
    "unknown top level operator: \\$",
    "BSONTypeError",
    "BSONError",
    "\\$err",
    "errmsg",
    "E11000",
    # Mongoose ODM
    "CastError",
    "Cast to \\w+ failed",
    "ValidationError",
    "ValidatorError",
    "ObjectParameterError",
    "StrictModeError",
]

BRACKET_OPERATOR_PAYLOADS: list[tuple[str, str]] = [
    ("$ne", "1"),
    ("$gt", ""),
    ("$regex", ".*"),
    ("$artemisProbe", "1"),
]

JSON_OPERATOR_PAYLOADS: list[tuple[str, Any]] = [
    ("$ne", None),
    ("$gt", ""),
    ("$regex", ".*"),
    ("$artemisProbe", 1),
]

PARAMS_PER_BATCH = 50

BLIND_TRUE_OPERATOR = "$ne"
BLIND_FALSE_OPERATOR = "$eq"
