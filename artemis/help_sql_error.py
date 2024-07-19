# type: ignore
import sys
import uuid

sys.path.append("/opt/")

from karton.core import Task

from artemis.modules.sql_injection_detector import SqlInjectionDetector

current_task_1 = Task(
    error=["null"],
    headers={"origin": "port_scanner", "receiver": "sql_error", "service": "http", "type": "service"},
    headers_persistent={},
    _last_update=1720615679.5750272,
    orig_uid="{319f9d2d-f853-4ee7-ac56-16ef5c38e92e}:319f9d2d-f853-4ee7-ac56-16ef5c38e92e",
    parent_uid="181cb374-8e74-4159-bb39-147faad2b975",
    payload={
        "host": "172.18.0.4",
        "port": 80,
    },
    payload_persistent={
        "__headers_persistent": {},
        "disabled_modules": [
            "wordpress_plugins",
            "ReverseDNSLookup",
            "domain_expiration_scanner",
            "humble",
            "scripts_unregistered_domains",
            "device_identifier",
            "subdomain_enumeration",
            "robots",
            "ftp_bruter",
            "dns_scanner",
            "forti_vuln",
            "joomla_scanner",
            "nuclei",
            "sqlmap",
            "vcs",
            "directory_index",
            "wp_scanner",
            "example",
            "postgresql_bruter",
            "drupal_scanner",
            "wordpress_bruter",
            "ssh_bruter",
            "mysql_bruter",
            "bruter",
            "mail_dns_scanner",
        ],
        "original_ip": "172.18.0.4",
        "tag": "sql_error_test",
    },
    root_uid="8be8b741-ed7f-44a2-b80b-8356300a11ee",
    uid=str(uuid.uuid4()),
)

current_task_2 = Task(
    error=["null"],
    headers={"origin": "port_scanner", "receiver": "sql_error", "service": "http", "type": "service"},
    headers_persistent={},
    _last_update=1720615679.5750272,
    orig_uid="{319f9d2d-f853-4ee7-ac56-16ef5c38e92e}:319f9d2d-f853-4ee7-ac56-16ef5c38e92e",
    parent_uid="181cb374-8e74-4159-bb39-147faad2b975",
    payload={
        "host": "172.18.0.5",
        "port": 80,
    },
    payload_persistent={
        "__headers_persistent": {},
        "disabled_modules": [
            "wordpress_plugins",
            "ReverseDNSLookup",
            "domain_expiration_scanner",
            "humble",
            "scripts_unregistered_domains",
            "device_identifier",
            "subdomain_enumeration",
            "robots",
            "ftp_bruter",
            "dns_scanner",
            "forti_vuln",
            "joomla_scanner",
            "nuclei",
            "sqlmap",
            "vcs",
            "directory_index",
            "wp_scanner",
            "example",
            "postgresql_bruter",
            "drupal_scanner",
            "wordpress_bruter",
            "ssh_bruter",
            "mysql_bruter",
            "bruter",
            "mail_dns_scanner",
        ],
        "original_ip": "172.18.0.5",
        "tag": "sql_error_test",
    },
    root_uid="8be8b741-ed7f-44a2-b80b-8356300a11ee",
    uid=str(uuid.uuid4()),
)

sql_error = SqlInjectionDetector()
sql_error.run([current_task_1, current_task_2])
