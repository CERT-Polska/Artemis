from __future__ import annotations

from enum import Enum


class TaskType(str, Enum):
    """
    Types of tasks handled by the Artemis system.

    :cvar NEW: Unclassified data (goes to classifier).
    :cvar DOMAIN: Domain name (e.g., google.com).
    :cvar DOMAIN_THAT_MAY_NOT_EXIST: Domain name without existence filtering enabled.
    :cvar IP: IP address (e.g., 8.8.8.8).
    :cvar SERVICE: Service with host and port (e.g., google.com:443).
    :cvar WEBAPP: Web application with URL and type (e.g., WordPress).
    :cvar URL: HTTP URL, must have content attached.
    :cvar DEVICE: Device with host, port, SSL, and type (e.g., FortiOS).
    """

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
    """
    Supported network services.

    :cvar UNKNOWN: Unknown service type.
    :cvar FTP: FTP service.
    :cvar HTTP: HTTP/HTTPS service.
    :cvar SMTP: SMTP service.
    :cvar IMAP: IMAP service.
    :cvar MYSQL: MySQL service.
    :cvar POSTGRESQL: PostgreSQL service.
    :cvar SSH: SSH service.
    """

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
    """
    Supported web application types.

    :cvar UNKNOWN: Unknown web application type.
    :cvar WORDPRESS: WordPress CMS.
    :cvar JOOMLA: Joomla CMS.
    :cvar DRUPAL: Drupal CMS.
    :cvar EZPUBLISH: eZ Publish CMS.
    :cvar TYPESETTER: Typesetter CMS.
    :cvar ROUNDCUBE: Roundcube webmail.
    :cvar MOODLE: Moodle LMS.
    """

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
    """
    Supported device types.

    :cvar UNKNOWN: Unknown device type.
    :cvar FORTIOS: FortiOS device.
    :cvar PANOSGP: Palo Alto Networks GlobalProtect device.
    """

    UNKNOWN = "unknown"

    FORTIOS = "fortios"
    PANOSGP = "panos-globalprotect"


class TaskStatus(str, Enum):
    """
    Status values for Karton tasks.

    :cvar OK: The task completed successfully and no issues were found.
    :cvar ERROR: The task encountered an error during processing.
    :cvar INTERESTING: The task completed and found something noteworthy (e.g., a vulnerability).
    """

    OK = "OK"
    ERROR = "ERROR"
    INTERESTING = "INTERESTING"
