SQL_ERROR_MESSAGES = [
    "SQL syntax.{0,200}?MySQL",
    "Warning.{0,200}?\\Wmysqli?_",
    "MySQLSyntaxErrorException",
    "valid MySQL result",
    "check the manual that (corresponds to|fits) your MySQL server version",
    "Unknown column '[^ ]+' in 'field list'",
    "MySqlClient\\.",
    "com\\.mysql\\.jdbc",
    "Zend_Db_(Adapter|Statement)_Mysqli_Exception",
    "Pdo[./_\\\\]Mysql",
    "MySqlException",
    "SQLSTATE\\[\\d+\\]: Syntax error or access violation",
    "Something is wrong in your syntax",
    # MariaDB,
    "check the manual that (corresponds to|fits) your MariaDB server version",
    # Drizzle,
    "check the manual that (corresponds to|fits) your Drizzle server version",
    # MemSQL,
    "MemSQL does not support this type of query",
    "is not supported by MemSQL",
    "unsupported nested scalar subselect",
    # PostgreSQL,
    "PostgreSQL.{0,200}?ERROR",
    "Warning.{0,200}?\\Wpg_",
    "valid PostgreSQL result",
    "Npgsql\\.",
    "PG::SyntaxError:",
    "org\\.postgresql\\.util\\.PSQLException",
    "ERROR:\\s\\ssyntax error at or near",
    "ERROR: parser: parse error at or near",
    "PostgreSQL query failed",
    "org\\.postgresql\\.jdbc",
    "Pdo[./_\\\\]Pgsql",
    "PSQLException",
    "pg_stat_progress",
    # Microsoft SQL Server,
    "Driver.{0,200}? SQL[\\-\\_\\ ]{0,200}Server",
    "OLE DB.{0,200}? SQL Server",
    "\\bSQL Server[^&lt;&quot;]+Driver",
    "Warning.{0,200}?\\W(mssql|sqlsrv)_",
    "\\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
    "System\\.Data\\.SqlClient\\.SqlException\\.(SqlException|SqlConnection\\.OnError)",
    "(?s)Exception.{0,200}?\\bRoadhouse\\.Cms\\.",
    "Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
    "\\[SQL Server\\]",
    "ODBC SQL Server Driver",
    "ODBC Driver \\d+ for SQL Server",
    "SQLServer JDBC Driver",
    "com\\.jnetdirect\\.jsql",
    "macromedia\\.jdbc\\.sqlserver",
    "Zend_Db_(Adapter|Statement)_Sqlsrv_Exception",
    "com\\.microsoft\\.sqlserver\\.jdbc",
    "Pdo[./_\\\\](Mssql|SqlSrv)",
    "SQL(Srv|Server)Exception",
    "Unclosed quotation mark after the character string",
    # Microsoft Access,
    "Microsoft Access (\\d+ )?Driver",
    "JET Database Engine",
    "Access Database Engine",
    "ODBC Microsoft Access",
    "Syntax error \\(missing operator\\) in query expression",
    # Oracle,
    "\\bORA-\\d{5}",
    "Oracle error",
    "Oracle.{0,200}?Driver",
    "Warning.{0,200}?\\W(oci|ora)_",
    "quoted string not properly terminated",
    "SQL command not properly ended",
    "macromedia\\.jdbc\\.oracle",
    "oracle\\.jdbc",
    "Zend_Db_(Adapter|Statement)_Oracle_Exception",
    "Pdo[./_\\\\](Oracle|OCI)",
    "OracleException",
    # IBM DB2,
    "CLI Driver.{0,200}?DB2",
    "DB2 SQL error",
    "\\bdb2_\\w+\\(",
    "SQLCODE[=:\\d, -]+SQLSTATE",
    "com\\.ibm\\.db2\\.jcc",
    "Zend_Db_(Adapter|Statement)_Db2_Exception",
    "Pdo[./_\\\\]Ibm",
    "DB2Exception",
    "ibm_db_dbi\\.ProgrammingError",
    # Informix,
    "Warning.{0,200}?\\Wifx_",
    "Exception.{0,200}?Informix",
    "Informix ODBC Driver",
    "ODBC Informix driver",
    "com\\.informix\\.jdbc",
    "weblogic\\.jdbc\\.informix",
    "Pdo[./_\\\\]Informix",
    "IfxException",
    # Firebird,
    "Dynamic SQL Error",
    "Warning.{0,200}?\\Wibase_",
    "org\\.firebirdsql\\.jdbc",
    "Pdo[./_\\\\]Firebird",
    # SQLite,
    "SQLite/JDBCDriver",
    "SQLite\\.Exception",
    "(Microsoft|System)\\.Data\\.SQLite\\.SQLiteException",
    "Warning.{0,200}?\\W(sqlite_|SQLite3::)",
    "\\[SQLITE_ERROR\\]",
    "SQLite error \\d+:",
    "sqlite3.OperationalError:",
    "SQLite3::SQLException",
    "org\\.sqlite\\.JDBC",
    "Pdo[./_\\\\]Sqlite",
    "SQLiteException",
    # SAP MaxDB,
    "SQL error.{0,200}?POS([0-9]+)",
    "Warning.{0,200}?\\Wmaxdb_",
    "DriverSapDB",
    "-3014.{0,200}?Invalid end of SQL statement",
    "com\\.sap\\.dbtech\\.jdbc",
    "\\[-3008\\].{0,200}?: Invalid keyword or missing delimiter",
    # Sybase,
    "Warning.{0,200}?\\Wsybase_",
    "Sybase message",
    "Sybase.{0,200}?Server message",
    "SybSQLException",
    "Sybase\\.Data\\.AseClient",
    "com\\.sybase\\.jdbc",
    # Ingres,
    "Warning.{0,200}?\\Wingres_",
    "Ingres SQLSTATE",
    "Ingres\\W.{0,200}?Driver",
    "com\\.ingres\\.gcf\\.jdbc",
    # FrontBase,
    "Exception (condition )?\\d+\\. Transaction rollback",
    "com\\.frontbase\\.jdbc",
    "Syntax error 1. Missing",
    "(Semantic|Syntax) error [1-4]\\d{2}\\.",
    # HSQLDB,
    "Unexpected end of command in statement \\[",
    "Unexpected token.{0,200}?in statement \\[",
    "org\\.hsqldb\\.jdbc",
    # H2,
    "org\\.h2\\.jdbc",
    "\\[42000-192\\]",
    # MonetDB,
    "![0-9]{5}![^\\n]+(failed|unexpected|error|syntax|expected|violation|exception)",
    "\\[MonetDB\\]\\[ODBC Driver",
    "nl\\.cwi\\.monetdb\\.jdbc",
    # Apache Derby,
    "Syntax error: Encountered",
    "org\\.apache\\.derby",
    "ERROR 42X01",
    # Vertica,
    ", Sqlstate: (3F|42).{3}, (Routine|Hint|Position):",
    "/vertica/Parser/scan",
    "com\\.vertica\\.jdbc",
    "org\\.jkiss\\.dbeaver\\.ext\\.vertica",
    "com\\.vertica\\.dsi\\.dataengine",
    # Mckoi,
    "com\\.mckoi\\.JDBCDriver",
    "com\\.mckoi\\.database\\.jdbc",
    "&lt;REGEX_LITERAL&gt;",
    # Presto,
    "com\\.facebook\\.presto\\.jdbc",
    "io\\.prestosql\\.jdbc",
    "com\\.simba\\.presto\\.jdbc",
    "UNION query has different number of fields: \\d+, \\d+",
    # Altibase,
    "Altibase\\.jdbc\\.driver",
    # MimerSQL,
    "com\\.mimer\\.jdbc",
    "Syntax error,[^\\n]+assumed to mean",
    # CrateDB,
    "io\\.crate\\.client\\.jdbc",
    # Cache,
    "encountered after end of query",
    "A comparison operator is required here",
    # Raima Database Manager,
    "-10048: Syntax error",
    "rdmStmtPrepare\\(.+?\\) returned",
    # Virtuoso,
    "SQ074: Line \\d+:",
    "SR185: Undefined procedure",
    "SQ200: No table ",
    "Virtuoso S0002 Error",
    "\\[(Virtuoso Driver|Virtuoso iODBC Driver)\\]\\[Virtuoso Server\\]",
]

URL_PARAMS = [
    "a",
    "act",
    "action",
    "action2",
    "activate",
    "activated",
    "active",
    "add",
    "address",
    "admin",
    "admin_email",
    "admin_password",
    "ajax",
    "_ajax_nonce",
    "alias",
    "all",
    "allusers",
    "amount",
    "api_key",
    "attachment",
    "attachment_id",
    "attachments",
    "auth",
    "author",
    "blog",
    "blog_public",
    "body",
    "c",
    "callback",
    "cancel",
    "captcha",
    "cat",
    "category",
    "category_id",
    "charset",
    "check",
    "checked",
    "checkemail",
    "cid",
    "city",
    "class",
    "client_id",
    "clone",
    "cmd",
    "code",
    "color",
    "columns",
    "command",
    "comment",
    "comment_ID",
    "comments",
    "comment_status",
    "config",
    "confirm",
    "content",
    "context",
    "cookie",
    "copy",
    "count",
    "country",
    "create",
    "csrf_token",
    "customized",
    "d",
    "data",
    "database",
    "date",
    "day",
    "db",
    "db_name",
    "dbname",
    "db_port",
    "debug",
    "del",
    "delete",
    "deleted",
    "delete_widget",
    "desc",
    "description",
    "destination",
    "dir",
    "direction",
    "directory",
    "disabled",
    "dismiss",
    "dl",
    "do",
    "domain",
    "down",
    "download",
    "drop",
    "dump",
    "e",
    "edit",
    "edit",
    "email",
    "enable",
    "enabled",
    "end",
    "end_date",
    "error",
    "event",
    "excerpt",
    "export",
    "f",
    "features",
    "fid",
    "field",
    "field_id",
    "fields",
    "file",
    "file_name",
    "filename",
    "files",
    "filter",
    "firstname",
    "first_name",
    "flag",
    "fname",
    "folder",
    "foo",
    "form",
    "format",
    "from",
    "function",
    "g",
    "gid",
    "gmt_offset",
    "go",
    "g",
    "group",
    "group_id",
    "groups",
    "h",
    "hash",
    "height",
    "hidden",
    "history",
    "host",
    "hostname",
    "html",
    "i",
    "id",
    "ID",
    "id_base",
    "ids",
    "image",
    "img",
    "import",
    "index",
    "info",
    "input",
    "insert",
    "invalid",
    "ip",
    "item",
    "items",
    "json",
    "key",
    "keyword",
    "keywords",
    "l",
    "label",
    "lang",
    "language",
    "lastname",
    "last_name",
    "level",
    "limit",
    "link",
    "linkcheck",
    "link_id",
    "link_url",
    "list",
    "locale",
    "location",
    "log",
    "loggedout",
    "login",
    "logout",
    "m",
    "mail",
    "md5",
    "media",
    "menu",
    "message",
    "meta",
    "metakeyinput",
    "metakeyselect",
    "_method",
    "method",
    "mobile",
    "mod",
    "mode",
    "modify",
    "module",
    "month",
    "move",
    "msg",
    "multi_number",
    "n",
    "name",
    "new",
    "newcontent",
    "newname",
    "new_role",
    "next",
    "nickname",
    "noconfirmation",
    "noheader",
    "nonce",
    "note",
    "notes",
    "ns",
    "num",
    "number",
    "o",
    "oauth_token",
    "oauth_verifier",
    "object",
    "offset",
    "oitar",
    "op",
    "opt",
    "option",
    "options",
    "order",
    "orderby",
    "order_id",
    "output",
    "out_trade_no",
    "overwrite",
    "p",
    "page",
    "paged",
    "page_id",
    "params",
    "parent",
    "parent_id",
    "part",
    "pass1",
    "pass",
    "pass2",
    "passwd",
    "password",
    "path",
    "phone",
    "pid",
    "plugin",
    "plugins",
    "plugin_status",
    "port",
    "position",
    "post",
    "postid",
    "post_id",
    "post_ID",
    "post_mime_type",
    "post_status",
    "post_title",
    "post_type",
    "prefix",
    "preview",
    "preview_id",
    "preview_nonce",
    "product_id",
    "profile",
    "provider",
    "pwd",
    "q",
    "query",
    "r",
    "range",
    "reason",
    "redirect",
    "redirect_to",
    "ref",
    "referer",
    "rememberme",
    "remove",
    "rename",
    "replytocom",
    "request",
    "reset",
    "return",
    "reverse",
    "revision",
    "role",
    "rows",
    "s",
    "save",
    "screen",
    "script",
    "search",
    "secret",
    "section",
    "select",
    "selection",
    "send",
    "server",
    "service",
    "set",
    "settings",
    "settings",
    "shortcode",
    "show",
    "show_sticky",
    "sid",
    "sidebar",
    "signature",
    "signup_for",
    "site",
    "site_id",
    "size",
    "slug",
    "sort",
    "source",
    "sql",
    "src",
    "st",
    "stage",
    "start",
    "start_date",
    "state",
    "status",
    "step",
    "sticky",
    "string",
    "stylesheet",
    "subject",
    "submit",
    "success",
    "t",
    "tab",
    "table",
    "tablename",
    "tables",
    "tag",
    "tag_ID",
    "tags",
    "target",
    "task",
    "tax",
    "tax_input",
    "taxonomy",
    "template",
    "term",
    "test",
    "text",
    "text",
    "theme",
    "themes",
    "tid",
    "time",
    "timeout",
    "timestamp",
    "timezone",
    "timezone_string",
    "title",
    "to",
    "token",
    "trashed",
    "trigger",
    "type",
    "u",
    "uid",
    "uname",
    "untrashed",
    "up",
    "update",
    "updated",
    "upload",
    "url",
    "user",
    "user_email",
    "user_id",
    "userid",
    "user_login",
    "username",
    "user_name",
    "users",
    "v",
    "val",
    "value",
    "version",
    "view",
    "w",
    "weblog_title",
    "what",
    "where",
    "widget",
    "widget_id",
    "widget",
    "width",
    "_wp_http_referer",
    "_wpnonce",
    "wp_screen_options",
    "x",
    "xml",
    "y",
    "year",
]
