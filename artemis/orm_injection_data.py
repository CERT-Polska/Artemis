# Common parameter names to probe on endpoints that have no existing query parameters.
# These are typical names found in Django views, DRF filters, and admin panels.
COMMON_PARAM_NAMES = [
    "id",
    "name",
    "username",
    "email",
    "search",
    "q",
    "query",
    "title",
    "slug",
    "status",
    "type",
    "page",
    "order",
    "sort",
    "filter",
]

ORM_LOOKUP_SUFFIXES = [
    "__exact",
    "__iexact",
    "__contains",
    "__icontains",
    "__startswith",
    "__istartswith",
    "__endswith",
    "__iendswith",
    "__gt",
    "__gte",
    "__lt",
    "__lte",
    "__regex",
    "__iregex",
]

SENSITIVE_FIELD_PROBES = [
    ("password", "startswith", "pbkdf2"),
    ("password", "startswith", "bcrypt"),
    ("password", "startswith", "argon2"),
    ("password", "contains", "$"),
    ("is_staff", "exact", "1"),
    ("is_superuser", "exact", "1"),
    ("is_admin", "exact", "1"),
    ("email", "contains", "@"),
]
