from __future__ import annotations

from enum import Enum


class TaskType(str, Enum):
    # unclassified data (goes to classifier)
    NEW = "new"

    # {domain: lidl.com}
    DOMAIN = "domain"

    # {ip: 8.8.8.8}
    IP = "ip"

    # {service: lidl.com:443}
    SERVICE = "service"

    # {webapp: having a URL, e.g. https://lidl.com/new/, and a type, e.g. WebApplication.WORDPRESS}
    WEBAPP = "webapp"

    # {URL: just a HTTP URL with content to make further work easier}
    URL = "url"


class Service(str, Enum):
    # Each of the services can have the SSL flag enabled - therefore HTTP covers both HTTP and HTTPS.

    UNKNOWN = "unknown"
    FTP = "ftp"
    HTTP = "http"
    SMTP = "smtp"
    IMAP = "imap"
    MYSQL = "mysql"
    POSTGRES = "postgres"

    @classmethod
    def _missing_(cls, value: object) -> Service:
        return Service.UNKNOWN


class WebApplication(str, Enum):
    UNKNOWN = "unknown"

    WORDPRESS = "wordpress"
    JOOMLA = "joomla"
    DRUPAL = "drupal"
    EZPUBLISH = "ezpublish"
    TYPESETTER = "typesetter"

    ROUNDCUBE = "roundcube"

    MOODLE = "moodle"

    IDRAC = "idrac"

    @classmethod
    def _missing_(cls, value: object) -> WebApplication:
        return WebApplication.UNKNOWN


class TaskStatus(str, Enum):
    OK = "OK"
    ERROR = "ERROR"
    INTERESTING = "INTERESTING"
