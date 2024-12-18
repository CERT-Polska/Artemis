from __future__ import annotations

from enum import Enum


class TaskType(str, Enum):
    # unclassified data (goes to classifier)
    NEW = "new"

    # {domain: google.com}
    DOMAIN = "domain"

    # {domain: google.com but without existence filtering enabled}
    DOMAIN_THAT_MAY_NOT_EXIST = "domain_that_may_not_exist"

    # {ip: 8.8.8.8}
    IP = "ip"

    # {service: google.com:443}
    SERVICE = "service"

    # {webapp: having a URL, e.g. https://google.com/new/, and a type, e.g. WebApplication.WORDPRESS}
    WEBAPP = "webapp"

    # {URL: just a HTTP URL. Must have content attached to make further operations faster}
    URL = "url"

    # {device: having a host, port, ssl, and a device type, e.g. Device.FORTIOS}
    DEVICE = "device"


class Service(str, Enum):
    # Each of the services can have the SSL flag enabled - therefore HTTP covers both HTTP and HTTPS.

    UNKNOWN = "unknown"
    FTP = "ftp"
    HTTP = "http"
    SMTP = "smtp"
    IMAP = "imap"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    SSH = "ssh"

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

    @classmethod
    def _missing_(cls, value: object) -> WebApplication:
        return WebApplication.UNKNOWN


class Device(str, Enum):
    UNKNOWN = "unknown"

    FORTIOS = "fortios"
    PANOSGP = "panos-globalprotect"


class TaskStatus(str, Enum):
    OK = "OK"
    ERROR = "ERROR"
    INTERESTING = "INTERESTING"
