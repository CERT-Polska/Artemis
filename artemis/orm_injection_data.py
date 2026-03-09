from typing import Dict, List

from artemis.config import Config

ORM_ERROR_MESSAGES: List[str] = [
    # SQLAlchemy (most common in Python web apps)
    "sqlalchemy\\.exc\\.(?:ProgrammingError|OperationalError|StatementError|DBAPIError|ArgumentError)",
    "sqlalchemy\\.exc\\.(?:IntegrityError|InternalError|NotSupportedError)",
    # Django ORM
    "django\\.db\\.utils\\.(?:ProgrammingError|OperationalError|DataError|InternalError|NotSupportedError)",
    # Peewee (Python)
    "peewee\\.(?:OperationalError|ProgrammingError|DataError|IntegrityError)",
    # Sequelize (Node.js)
    "Sequelize(?:Database|Query|Connection|Validation)Error",
    "sequelize\\.(?:DatabaseError|QueryError)",
    # TypeORM (Node.js)
    "QueryFailedError",
    "typeorm\\.",
    # Prisma (Node.js)
    "PrismaClient(?:KnownRequestError|UnknownRequestError|RustPanicError)",
    # Hibernate / JPA (Java)
    "org\\.hibernate\\.(?:QueryException|exception\\.)",
    "javax\\.persistence\\.(?:PersistenceException|QueryTimeoutException|PersistenceException)",
    # ActiveRecord (Ruby)
    "ActiveRecord::(?:StatementInvalid|PreparedStatementInvalid|Database(?:Error)?)",
    "ActiveRecord",
    # Doctrine / Eloquent (PHP)
    "Doctrine\\\\DBAL\\\\(?:Exception|Driver)",
    "Illuminate\\\\Database\\\\(?:QueryException|DatabaseManager)",
    # CakePHP
    "CakePHP.*(?:Database|Query)",
    # Propel ORM (PHP/Java)
    "Propel.*Exception",
    # Entity Framework (.NET)
    "(?:EntityCommandCompilationException|EntitySqlException|EntityException)",
    "Microsoft\\.EntityFrameworkCore\\.DbUpdateException",
    # Sqlalchemy psycopg2 specific
    "psycopg2\\.(?:ProgrammingError|OperationalError|IntegrityError)",
    # Generic/catchall patterns
    "(?:SQL|Database)Error.*(?:at|in|near)",
    "(?:Query|Statement).*(?:Error|Exception)",
]

HEADERS: Dict[str, str] = {
    "Accept": "application/xml, application/json, text/plain, text/html",
    "Accept-Encoding": "acceptencoding",
    "Accept-Language": "acceptlanguage",
    "Access-Control-Request-Headers": "accesscontrolrequestheaders",
    "Access-Control-Request-Method": "accesscontrolrequestmethod",
    "Authentication": "Bearer authenticationbearer",
    "Cookie": "cookiename=cookievalue",
    "Location": "location",
    "Origin": "origin",
    "Referer": "referer",
    "Upgrade-Insecure-Requests": "upgradeinsecurerequests",
    "User-Agent": Config.Miscellaneous.CUSTOM_USER_AGENT
    or "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41",
    "X-Api-Version": "xapiversion",
    "X-CSRF-Token": "xcsrftoken",
    "X-Druid-Comment": "xdruidcomment",
    "X-Forwarded-For": "xforwardedfor",
    "X-Origin": "xorigin",
    "accept-charset": "acceptcharset",
    "appversion": "appversion",
    "authorization": "authorization",
    "cache-control": "cachecontrol",
    "cf-connecting-ip": "cfconnectingip",
    "cf-ipcountry": "cfipcountry",
    "cf-visitor": "cfvisitor",
    "client-ip": "clientip",
    "dnt": "dnt",
    "forwarded-for": "forwardedfor",
    "forwarded": "forwarded",
    "front-end-https": "frontendhttps",
    "if-modified-since": "ifmodifiedsince",
    "if-none-match": "ifnonematch",
    "profile": "profile",
    "proxy": "proxy",
    "scheme": "scheme",
    "socketlog": "socketlog",
    "via": "via",
    "x-file-name": "xfilename",
    "x-firephp-version": "xfirephpversion",
    "x-forwarded-host": "xforwardedhost",
    "x-forwarded-port": "xforwardedport",
    "x-forwarded-prefix": "xforwardedprefix",
    "x-forwarded-proto": "xforwardedproto",
    "x-forwarded-server": "xforwardedserver",
    "x-forwarded-ssl": "xforwardedssl",
    "x-forwarded": "xforwarded",
    "x-method-override": "xmethodoverride",
    "x-moz": "xmoz",
    "x-original-host": "xoriginalhost",
    "x-original-url": "xoriginalurl",
    "x-pjax": "xpjax",
    "x-real-host": "xrealhost",
    "x-real-ip": "xrealip",
    "x-requested-with": "xrequestedwith",
    "x-rewrite-url": "xrewriteurl",
    "x-wap-profile": "xwapprofile",
    "x-wp-nonce": "xwpnonce",
}
