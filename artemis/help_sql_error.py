# type: ignore
import datetime
import sys
import uuid


sys.path.append("/opt/")

# from artemis.reporting.modules.sql_injection_detector.reporter import SqlInjectionDetectorReporter
# from artemis.modules.sql_injection_detector import SqlInjectionDetector
from karton.core import Task

from artemis.modules.dalfox import DalFox
# from artemis.reporting.modules.sql_injection_detector.reporter import SqlInjectionDetectorReporter
# from artemis.modules.sql_injection_detector import SqlInjectionDetector
# from artemis.modules.nuclei import Nuclei


current_task_1 = Task(
    error=["null"],
    headers={"service": "http", "receiver": "dalfox", "type": "service"},
    headers_persistent={},
    _last_update=1720615679.5750272,
    orig_uid="{319f9d2d-f853-4ee7-ac56-16ef5c38e92e}:319f9d2d-f853-4ee7-ac56-16ef5c38e92e",
    parent_uid="181cb374-8e74-4159-bb39-147faad2b975",
    payload={
        "host": "test_apache-with-sql-injection-xss",
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
        "original_ip": "172.18.0.9",
        "tag": "dalfox",
    },
    root_uid="8be8b741-ed7f-44a2-b80b-8356300a11ee",
    uid=str(uuid.uuid4()),
)
#
# current_task_2 = Task(
#     error=["null"],
#     headers={"origin": "port_scanner", "receiver": "sql_injection:core", "service": "http", "type": "service"},
#     headers_persistent={},
#     _last_update=1720615679.5750272,
#     orig_uid="{319f9d2d-f853-4ee7-ac56-16ef5c38e92e}:319f9d2d-f853-4ee7-ac56-16ef5c38e92e",
#     parent_uid="181cb374-8e74-4159-bb39-147faad2b975",
#     payload={
#         "host": "apache-with-sql-injection-postgres_second",
#         "port": 80,
#     },
#     payload_persistent={
#         "__headers_persistent": {},
#         "disabled_modules": [
#             "wordpress_plugins",
#             "ReverseDNSLookup",
#             "domain_expiration_scanner",
#             "humble",
#             "scripts_unregistered_domains",
#             "device_identifier",
#             "subdomain_enumeration",
#             "robots",
#             "ftp_bruter",
#             "dns_scanner",
#             "forti_vuln",
#             "joomla_scanner",
#             "nuclei",
#             "sqlmap",
#             "vcs",
#             "directory_index",
#             "wp_scanner",
#             "example",
#             "postgresql_bruter",
#             "drupal_scanner",
#             "wordpress_bruter",
#             "ssh_bruter",
#             "mysql_bruter",
#             "bruter",
#             "mail_dns_scanner",
#         ],
#         "original_ip": "172.18.0.8",
#         "tag": "sql_error_test",
#     },
#     root_uid="8be8b741-ed7f-44a2-b80b-8356300a11ee",
#     uid=str(uuid.uuid4()),
# )

# sql_error = SqlInjectionDetector()
# sql_error.run(current_task_1)

# nuclei = Nuclei()
# nuclei.run_multiple([current_task_2, current_task_1])

dal_fox = DalFox()
dal_fox.run(current_task_1)


# reporter = SqlInjectionDetectorReporter()
# a = reporter.create_reports(
#     task_result={
#         "task_host": "172.18.0.70:80",
#         "status": "INTERESTING",
#         "message": ["to jest error"],
#         "headers": {
#             "origin": "port_scanner",
#             "receiver": "sql_injection:core",
#             "service": "http",
#             "type": "service"
#         },
#         "created_at": datetime.datetime.utcnow(),
#         "result": {"credentials": "dsd"},
#         "payload": {
#             "host": "172.18.0.70:80",
#         },
#         "payload_persistent": {
#             "__headers_persistent": {},
#             "disabled_modules": [
#                 "wordpress_plugins",
#                 "ReverseDNSLookup",
#                 "domain_expiration_scanner",
#                 "humble",
#                 "scripts_unregistered_domains",
#                 "device_identifier",
#                 "subdomain_enumeration",
#                 "robots",
#                 "ftp_bruter",
#                 "dns_scanner",
#                 "forti_vuln",
#                 "joomla_scanner",
#                 "nuclei",
#                 "sqlmap",
#                 "vcs",
#                 "directory_index",
#                 "wp_scanner",
#                 "example",
#                 "postgresql_bruter",
#                 "drupal_scanner",
#                 "wordpress_bruter",
#                 "ssh_bruter",
#                 "mysql_bruter",
#                 "bruter",
#                 "mail_dns_scanner",
#             ],
#             "original_ip": "172.18.0.71",
#             "tag": "sql_error_test",
#         },
#     },
#     language="en_US"
# )
# #
# print(a)