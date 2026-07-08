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
