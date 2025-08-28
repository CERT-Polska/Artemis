admin_panel_login_bruter
^^^^^^^^^^^^^^^^^^^^^^^^
Attempts to brute-force login pages of admin panels using common credentials.

api_scanner
^^^^^^^^^^^
Scans API endpoints for vulnerabilities using OpenAPI/Swagger specifications.

bruter
^^^^^^
Brute-forces common paths such as ``/index.php.bak``.

device_identifier
^^^^^^^^^^^^^^^^^
Tries to identify the device (FortiOS, ...) and triggers downstream modules testing respective devices, if such modules exist.

directory_index
^^^^^^^^^^^^^^^
Detects directory index enabled on the server by checking paths mentioned in the home page source (e.g. with ``<link href="/styles/..." ...>``).

dns_scanner
^^^^^^^^^^^
Check for zone transfer and some known bad nameservers.

domain_expiration_scanner
^^^^^^^^^^^^^^^^^^^^^^^^^
Alerts if domain expiration date is coming.

drupal_scanner
^^^^^^^^^^^^^^
Drupal scanner - checks whether the version is obsolete.

example
^^^^^^^
An example Artemis module that shows how to implement one. Look into ``artemis/reporting/modules/example/`` to learn how to add findings from this module to the HTML reports.

ftp_bruter
^^^^^^^^^^
Performs a brute force attack on FTP servers to guess login and password.

humble
^^^^^^
Runs humble - A HTTP Headers Analyzer.

IPLookup
^^^^^^^^
Resolves IP addresses of domains so that HTTP-related modules can be run on the IPs directly.

joomla_extensions
^^^^^^^^^^^^^^^^^
Checks whether Joomla! extensions are up-to-date.

joomla_scanner
^^^^^^^^^^^^^^
Joomla scanner - checks whether the version is old or registration is enabled.

lfi_detector
^^^^^^^^^^^^
Module for detecting Local File Inclusion (LFI) vulnerabilities.

mail_dns_scanner
^^^^^^^^^^^^^^^^
Checks whether there is a mail server associated with the current domain and checks if SPF and DMARC records are present.

mysql_bruter
^^^^^^^^^^^^
Performs a brute force attack on MySQL servers to guess login and password.

nuclei
^^^^^^
Runs Nuclei templates on URLs.

port_scanner
^^^^^^^^^^^^
Scans ports with ``naabu`` and fingerprints the services with ``fingerprintx``.

postgresql_bruter
^^^^^^^^^^^^^^^^^
Performs a brute force attack on PostgreSQL servers to guess login and password.

removed_domain_existing_vhost
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Checks that despite removing domain, the corresponding vhost still exists on the server (if a data source is configured).

ReverseDNSLookup
^^^^^^^^^^^^^^^^
Performs reverse DNS lookup of IP addresses.

robots
^^^^^^
Looks for robots.txt file, triggers a scan of found URLs and checks whether the paths have a directory index enabled.

scripts_unregistered_domains
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Checks, whether scripts are loaded from unregistered domains

shodan_vulns
^^^^^^^^^^^^
Lists vulnerabilities from Shodan (if an API key is configured)

sql_injection_detector
^^^^^^^^^^^^^^^^^^^^^^
Module for detecting SQL injection and time-based SQL injection vulnerabilities.

ssh_bruter
^^^^^^^^^^
Performs a brute force attack on SSH.

subdomain_enumeration
^^^^^^^^^^^^^^^^^^^^^
Enumerates subdomains using ``gau``, ``subfinder`` and DNS brute-forcing.

vcs
^^^
Tries to find exposed git/SVN/Mercurial repositories.

webapp_identifier
^^^^^^^^^^^^^^^^^
Tries to identify the web application such as WordPress, Drupal or Joomla! and triggers modules that check the security of various applications.

wordpress_bruter
^^^^^^^^^^^^^^^^
Performs a brute-force attack on WordPress credentials.

wordpress_plugins
^^^^^^^^^^^^^^^^^
Checks whether WordPress plugins are up-to-date.

wp_scanner
^^^^^^^^^^
WordPress scanner - checks e.g. whether the verson is secure or whether registration is enabled.
