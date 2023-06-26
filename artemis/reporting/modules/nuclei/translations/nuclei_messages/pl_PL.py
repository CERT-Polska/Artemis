# This is not a .po file because we want to build the translation results from parts - for example,
# glue a generic message describing what a RCE leads to to some messages.

RCE_EFFECT_DESCRIPTION = (
    " Korzystając z tej podatności, atakujący może wykonać dowolne polecenie systemowe i dzięki temu zmodyfikować "
    "treść strony, umieścić na niej szkodliwe oprogramowanie lub pobrać dane umieszczane przez użytkowników."
)

WORDPRESS_UPDATE_HINT = (
    " Rekomendujemy aktualizację i włączenie automatycznej aktualizacji systemu WordPress, wtyczek i szablonów."
)

WORDPRESS_CLOSED_PLUGIN_HINT = "Ponieważ ta wtyczka nie jest już wspierana, rekomendujemy jej usunięcie."

PLUGIN_UPDATE_HINT = " Rekomendujemy aktualizację wtyczki do najnowszej wersji."

UPDATE_HINT = " Rekomendujemy aktualizację oprogramowania do najnowszej wersji."

DEFAULT_CREDENTIALS_HINT = " Rekomendujemy zmianę domyślnych haseł."

BUG_FIX_HINT = " Rekomendujemy poprawienie tego błędu, a także sprawdzenie, czy podobne błędy nie występują również w innych miejscach."

DATA_HIDE_HINT = " Rekomendujemy, aby takie dane nie były dostępne publicznie."


TRANSLATIONS = {
    "WordPress Contact Form 7 before 5.3.2 allows unrestricted file upload and remote code execution because a filename may contain special characters.": "Wtyczka WordPress Contact Form 7 w wersji poniżej 5.3.2 zezwala na nieograniczone umieszczanie plików i zdalne wykonanie kodu ponieważ nazwa pliku może zawierać znaki specjalne."
    + RCE_EFFECT_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    'Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2 contains a buffer overflow vulnerability in the ScStoragePathFromUrl function in the WebDAV service that could allow remote attackers to execute arbitrary code via a long header beginning with "If <http://" in a PROPFIND request.': "Internet Information Services (IIS) 6.0 w Microsoft Windows Server 2003 R2 zawiera podatność typu buffer overflow, która może umożliwić atakującym wykonanie dowolnego kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "The JCK Editor component 6.4.4 for Joomla! allows SQL Injection via the jtreelink/dialogs/links.php parent parameter.": "Wtyczka Joomla! o nazwie JCK Editor w wersji 6.4.4 zawiera podatność SQL Injection - może to umożliwić atakujacemu pobranie zawartości bazy danych, w tym danych osobowych."
    + PLUGIN_UPDATE_HINT,
    "Programs using jt-jiffle, and allowing Jiffle script to be provided via network request, are susceptible to a Remote Code Execution as the Jiffle script is compiled into Java code via Janino, and executed. In particular, this affects the downstream GeoServer project Version < 1.1.22.": "Programy korzystające z narzędzia jt-jiffle i umożliwiające korzystanie ze skryptów Jiffle przekazywanych za pomocą żądania sieciowego są podatne na zdalne wykonanie kodu ponieważ skrypty Jiffle są kompilowane do języka Java i wykonywane. Ta podatność dotyczy w szczególności projektu GeoServer w wersji poniżej 1.1.22."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "QNAP QTS Photo Station External Reference is vulnerable to local file inclusion via an externally controlled reference to a resource vulnerability. If exploited, this could allow an attacker to modify system files. The vulnerability is fixed in the following versions: QTS 5.0.1: Photo Station 6.1.2 and later QTS 5.0.0/4.5.x: Photo Station 6.0.22 and later QTS 4.3.6: Photo Station 5.7.18 and later QTS 4.3.3: Photo Station 5.4.15 and later QTS 4.2.6: Photo Station 5.2.14 and later.": "QNAP QTS Photo Station External Reference zawiera podatność Local File Inclusion, co umożliwia atakującemu modyfikowanie plików systemowych."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Joomla! before 3.7.1 contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.": "Joomla! w wersji przed 3.7.1 zawiera podatność SQL Injection. Atakujący może pobrać wrażliwe informacje z bazy danych, zmodyfikować dane i wykonywać dowolne operacje administracyjne na podatnej stronie."
    + UPDATE_HINT,
    "WordPress Google Maps plugin before 7.11.18 contains a SQL injection vulnerability. The plugin includes /class.rest-api.php in the REST API and does not sanitize field names before a SELECT statement. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.": "Wtyczka WordPress o nazwie Google Maps w wersji poniżej 7.11.18 zawiera podatność SQL Injection. Atakujący może pobrać informacje z bazy danych, zmienić je lub wykonać dowolne operacje administracyjne na podatnej stronie."
    + WORDPRESS_UPDATE_HINT,
    "Confluence Server and Data Center contain an OGNL injection vulnerability that could allow an authenticated user, and in some instances an unauthenticated user, to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from  version 7.12.0 before 7.12.5. The vulnerable endpoints can be accessed by a non-administrator user or unauthenticated user if 'Allow people to sign up to create their account' is enabled. To check whether this is enabled go to COG > User Management > User Signup Options.": "Narzędzia Confluence Server i Confluence Data Center zawierają podatność OGNL Injection, która może umożliwić zalogowanym (a w niektórych sytuacjach niezalogowanym) użytkownikom wykonywanie dowolnego kodu. Podatne są wersje poniżej 6.13.23, od 6.14.0 poniżej 7.4.11, od 7.5.0 poniżej 7.11.6, oraz od 7.12.0 poniżej 7.12.5."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "WordPress Visitor Statistics plugin through 5.7 contains multiple unauthenticated SQL injection vulnerabilities. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.": "Wtyczka WordPress Visitor Statistics w wersji do 5.7 zawiera wiele podatności typu SQL Injection które można wykorzystać bez logowania. Atakujący może pobrać wrażliwe informacje z bazy danych, zmodyfikować dane i wykonywać dowolne operacje administracyjne na podatnej stronie."
    + WORDPRESS_UPDATE_HINT,
    "When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.": "Wykorzystując Apache JServ Protocol (AJP) należy zwracać szczególną uwagę ufając połączeniom przychodzącym do Apache Tomcat. Tomcat traktuje połączenia AJP jako bardziej zaufane niż np. połączenia HTTP. W wersjach Apache Tomcat od 9.0.0.M1 do 9.0.0.30, od 8.5.0 do 8.5.50 i od 7.0.0 do 7.0.99, połączenia AJP były domyślnie włączone na wszystkich interfejsach, na których nasłuchiwał Apache Tomcat. Jeśli takie połączenia są dostępne dla atakujacego, mogą potencjalnie doprowadzić do możliwości zdalnego wykonania kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "InfluxDB before 1.7.6 contains an authentication bypass vulnerability via the authenticate function in services/httpd/handler.go. A JWT token may have an empty SharedSecret (aka shared secret). An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.": "InfluxDB w wersji poniżej 1.7.6 zawiera podatność umożliwiającą ominięcie uwierzytelniania. Atakujący może pobrać wrażliwe informacje, modyfikować dane lub uruchomić nieautoryzowane operacje administracyjne na podatnej stronie."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "UnRaid <=6.80 allows remote unauthenticated attackers to execute arbitrary code.": "Narzędzie UnRaid w wersji do 6.80 zezwala atakującym na wykonywanie dowolnego kodu bez logowania."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "A Spring Boot Actuator heap dump was detected. A heap dump is a snapshot of JVM memory, which could expose environment variables and HTTP requests.": "Wykryto zrzut pamięci udostępniany przez narzędzie Spring Boot Actuator. W takim zrzucie mogą znajdować się np. informacje o konfiguracji serwera (w tym hasła do bazy danych) lub treść żądań HTTP, mogąca potencjalnie zawierać wrażliwe dane."
    + DATA_HIDE_HINT,
    "elFinder 2.1.58 is vulnerable to remote code execution. This can allow an attacker to execute arbitrary code and commands on the server hosting the elFinder PHP connector, even with minimal configuration.": "Narzędzie elFinder w wersji 2.1.58 umożliwia zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "elFinder 2.1.58 is impacted by multiple remote code execution vulnerabilities that could allow an attacker to execute arbitrary code and commands on the server hosting the elFinder PHP connector, even with minimal configuration.": "Narzędzie elFinder w wersji 2.1.58 umożliwia zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Jboss Application Server as shipped with Red Hat Enterprise Application Platform 5.2 is susceptible to a remote code execution vulnerability because  the doFilter method in the ReadOnlyAccessFilter of the HTTP Invoker does not restrict classes for which it performs deserialization, thus allowing an attacker to execute arbitrary code via crafted serialized data.": "Narzędzie Jboss Application Server dostarczane z Red Hat Enterprise Application Platform 5.2 umożliwia zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "GitLab CE/EE starting from 11.9 does not properly validate image files that were passed to a file parser, resulting in a remote command execution vulnerability. This template attempts to passively identify vulnerable versions of GitLab without the need for an exploit by matching unique hashes for the application-<hash>.css file in the header for unauthenticated requests. Positive matches do not guarantee exploitability. Tooling to find relevant hashes based on the semantic version ranges specified in the CVE is linked in the references section below.": "Narzędzie Gitlab CE/EE w niektórych wersjach od 11.9 nie waliduje poprawnie obrazków, co może prowadzić do możliwości zdalnego wykonania kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "An issue has been discovered in GitLab CE/EE affecting all versions starting from 12.10 before 14.6.5, all versions starting from 14.7 before 14.7.4, all versions starting from 14.8 before 14.8.2. An unauthorised user was able to steal runner registration tokens through an information disclosure vulnerability using quick actions commands.": "W narzędziu GitLab CE/EE w wersjach od 12.10 poniżej 14.6.5, od 14.7 poniżej 14.7.4 i od 14.8 poniżej 14.8.2 znaleziono podatność umożliwiającą pobieranie danych umożliwiających rejestrację dodatkowych maszyn wykonujących zadania CI, a w konsekwencji np. pobranie kodu źródłowego czy danych uwierzytelniających udostępnianych na potrzeby zadań CI."
    + UPDATE_HINT,
    "Jenkins 2.153 and earlier and LTS 2.138.3 and earlier are susceptible to a remote command injection via stapler/core/src/main/java/org/kohsuke/stapler/MetaClass.java that allows attackers to invoke some methods on Java objects by accessing crafted URLs that were not intended to be invoked this way.": "Jenkins w wersji 2.153 i wcześniejszych a także LTS 2.138.3 i wcześniejszych umożliwia zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "ProfilePress WordPress plugin  is susceptible to a vulnerability in the user registration component in the ~/src/Classes/RegistrationAuth.php file that makes it possible for users to register on sites as an administrator.": "Wtyczka WordPress o nazwie ProfilePress zawiera podatność umożliwiającą rejestrację jako administrator."
    + RCE_EFFECT_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "The Paid Memberships Pro WordPress Plugin, version < 2.9.8, is affected by an unauthenticated SQL injection vulnerability in the 'code' parameter of the '/pmpro/v1/order' REST route.": "Wtyczka WordPress o nazwie Paid Memberships Pro w wersji poniżej 2.9.8 zawiera podatność SQL Injection, co umożliwia pobranie całej zawartości bazy danych."
    + WORDPRESS_UPDATE_HINT,
    "WordPress Paid Memberships Pro plugin before 2.9.8 contains a blind SQL injection vulnerability in the 'code' parameter of the /pmpro/v1/order REST route. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.": "Wtyczka WordPress o nazwie Paid Memberships Pro w wersji poniżej 2.9.8 zawiera podatność Blind SQL Injection, co umożliwia pobranie całej zawartości bazy danych."
    + WORDPRESS_UPDATE_HINT,
    "WordPress Paid Memberships Pro plugin before 2.6.7 is susceptible to blind SQL injection. The plugin does not escape the discount_code in one of its REST routes before using it in a SQL statement. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.": "Wtyczka WordPress o nazwie Paid Memberships Pro w wersji poniżej 2.6.7 zawiera podatność Blind SQL Injection, co umożliwia pobranie całej zawartości bazy danych."
    + WORDPRESS_UPDATE_HINT,
    "The debugging endpoint /debug/pprof is exposed over the unauthenticated Kubelet healthz port. This debugging endpoint can potentially leak sensitive information such as internal Kubelet memory addresses and configuration, or for limited denial of service. Versions prior to 1.15.0, 1.14.4, 1.13.8, and 1.12.10 are affected. The issue is of medium severity, but not exposed by the default configuration.": "Końcówka /debug/pprof jest udostępniona bez autoryzacji, co może umożliwiać pobranie wrażliwych danych lub atak typu DoS. Rekomendujemy, aby takie zasoby nie były dostępne publicznie.",
    "RockMongo 1.1.8 contains a cross-site scripting vulnerability which allows attackers to inject arbitrary JavaScript into the response returned by the application.": "RockMongo w wersji 1.1.8 zawiera podatność Cross-Site Scripting, która umożliwia wstrzykiwanie dowolnych skryptów JavaScript do odpowiedzi zwracanej przez aplikację."
    + UPDATE_HINT,
    "sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.": "sapi/cgi/cgi_main.c w PHP przed 5.3.12 i w gałęzi 5.4.x przed 5.4.2, gdy PHP jest uruchamiane jako skrypt CGI, niepoprawnie przetwarza parametry w adresie URL, co umożliwia zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "X-UI contains default credentials. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.": "Logowanie do X-UI za pomocą domyślnych danych jest możliwe. Atakujący może uzyskać dostęp do kont użytkowników, pobrać wrażliwe dane, modyfikować dane lub uruchomić nieuprawnione operacje."
    + DEFAULT_CREDENTIALS_HINT,
    "Cross-site scripting was discovered via a search for reflected parameter values in the server response via GET-requests.": "Wykryto podatność Reflected Cross-Site Scripting. Atakujący może spreparować link, który - gdy kliknięty przez administratora - wykona dowolną operację na stronie którą może wykonać administrator (taką jak np. modyfikację treści)."
    + BUG_FIX_HINT,
    "WordPress Statistic plugin versions prior to version 13.0.8 are affected by an unauthenticated time-based blind SQL injection vulnerability.": "Wersje wtyczki WordPress Statistics poniżej 13.0.8 zawierają podatność Time-based Blind SQL Injection, która umożliwia pobranie dowolnej informacji z bazy danych."
    + WORDPRESS_UPDATE_HINT,
    "ClamAV server 0.99.2, and possibly other previous versions, allow the execution\nof dangerous service commands without authentication. Specifically, the command 'SCAN'\nmay be used to list system files and the command 'SHUTDOWN' shut downs the service.": "Serwer ClamAV w wersji 0.99.2 (możliwe jest, że również w niektórych wcześniejszych wersjach) umożliwia uruchamianie niebezpiecznych komend bez uwierzytelnienia, co może skutkować np. pobraniem listy plików na serwerze lub wyłączeniem usługi."
    + UPDATE_HINT,
    "MAGMI (Magento Mass Importer) is vulnerable to cross-site request forgery (CSRF) due to a lack of CSRF tokens. Remote code execution (via phpcli command) is also possible in the event that CSRF is leveraged against an existing admin session.": "Wykryto, że narzędzie MAGMI (Magento Mass Importer) zawiera podatność Cross-Site Request Forgery, co może potencjalnie prowadzić do zdalnego wykonania kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Detects the possibility of SQL injection in 29 database engines. Inspired by https://github.com/sqlmapproject/sqlmap/blob/master/data/xml/errors.xml.": "Wykryto potencjalną podatność SQL Injection. Prosimy o weryfikację, czy ona występuje - jeśli tak, może to umożliwić atakującemu pobranie całej zawartości bazy danych."
    + BUG_FIX_HINT,
    "Detects potential SQL injection via error strings in 29 database engines. Inspired by https://github.com/sqlmapproject/sqlmap/blob/master/data/xml/errors.xml.": "Wykryto potencjalną podatność SQL Injection na podstawie wyświetlonego komunikatu o błędzie bazy danych. Prosimy o weryfikację, czy ona występuje - jeśli tak, może to umożliwić atakującemu pobranie całej zawartości bazy danych."
    + BUG_FIX_HINT,
    "WordPress WooCommerce plugin before 3.1.2 does not have authorisation and CSRF checks in the wpt_admin_update_notice_option AJAX action available to both unauthenticated and authenticated users as well as does not validate the callback parameter, allowing unauthenticated attackers to call arbitrary functions with either none or one user controlled argument.": "Wtyczka WooCommerce w wersji poniżej 3.1.2 zawiera podatność, która może prowadzić do zdalnego wykonania kodu przez niezalogowanego użytkownika."
    + RCE_EFFECT_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    'Apache Solr versions 8.8.1 and prior contain a server-side request forgery vulnerability. The ReplicationHandler (normally registered at "/replication" under a Solr core) in Apache Solr has a "masterUrl" (also "leaderUrl" alias) parameter that is used to designate another ReplicationHandler on another Solr core to replicate index data into the local core. To prevent a SSRF vulnerability, Solr ought to check these parameters against a similar configuration it uses for the "shards" parameter.': "Apache Solr w wersji 8.8.1 i wcześniejszych zawiera podatność Server-Side Request Forgery."
    + UPDATE_HINT,
    "ProFTPD 1.3.5 contains a remote code execution vulnerability via the mod_copy module which allows remote attackers to read and write to arbitrary files via the site cpfr and site cpto commands.": "ProFTPD w wersji 1.3.5 umożliwia zdalne wykonanie kodu, ponieważ moduł mod_copy zezwala atakującemu na odczyt i zapis dowolnych plików."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Oracle GlassFish Server Open Source Edition 3.0.1 (build 22) is vulnerable to unauthenticated local file inclusion vulnerabilities that allow remote attackers to request arbitrary files on the server.": "Narzędzie Oracle GlassFish Server Open Source Edition 3.0.1 (build 22) zawiera podatność umożliwiającą atakującym pobieranie dowolnych plików z serwera."
    + UPDATE_HINT,
    "Symfony profiler was detected.": "Wykryto narzędzie Symfony Profiler. Udostępnienie tego narzędzia może prowadzić np. do wycieku konfiguracji aplikacji (w tym haseł do bazy danych), kodu źródłowego lub innych informacji, które nie powinny być dostępne publicznie. Rekomendujemy, aby to narzędzie nie było dostępne publicznie.",
    "Flir is vulnerable to local file inclusion.": "Narzędzie Flir zawiera podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików z serwera.",
    "Redis server without any required authentication was discovered.": "Wykryto serwer Redis dostępny bez uwierzytelniania. Rekomendujemy, aby nie był dostępny publicznie.",
    "Generic J2EE Scan panel was detected. Looks for J2EE specific LFI vulnerabilities; tries to leak the web.xml file.": "Wykryto platformę J2EE zawierającą podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików z serwera."
    + BUG_FIX_HINT,
    "DotNetNuke (DNN) versions between 5.0.0 - 9.3.0 are affected by a deserialization vulnerability that leads to remote code execution.": "Narzędzie DotNetNuke (DNN) w wersjach pomiędzy 5.0.0 i 9.3.0 umożliwia zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Created by remote-ssh for Atom, contains SFTP/SSH server details and credentials": "Wykryto plik .ftpconfig zawierający dane logowania."
    + DATA_HIDE_HINT,
    "Concrete CMS before 8.5.2 contains a cross-site scripting vulnerability in preview_as_user function using cID parameter.": "Narzędzie Concrete CMS w wersji poniżej 8.5.2 zawiera podatność Cross-Site Scripting."
    + UPDATE_HINT,
    "Apache htpasswd configuration was detected.": "Wykryto plik .htpasswd (wykorzystywany przez serwer Apache) w którym znajduje się hasz hasła."
    + DATA_HIDE_HINT,
    "WordPress InPost Gallery plugin before 2.1.4.1 is susceptible to local file inclusion. The plugin insecurely uses PHP's extract() function when rendering HTML views, which can allow attackers to force inclusion of malicious files and URLs. This, in turn, can enable them to execute code remotely on servers.": "Wtyczka WordPress o nazwie InPost Gallery w wersjach poniżej 2.1.4.1 zawiera podatność która może prowadzić do zdalnego wykonania kodu."
    + RCE_EFFECT_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "FRP default login credentials were discovered.": "Wykryto, że domyślne dane do logowania do narzędzia FRP umożliwiają logowanie."
    + DEFAULT_CREDENTIALS_HINT,
    "An easily exploitable local file inclusion vulnerability allows unauthenticated attackers with network access via HTTP to compromise Oracle WebLogic Server. Supported versions that are affected are 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Successful attacks of this vulnerability can result in unauthorized and sometimes complete access to critical data.": "Serwer OracleWebLogic w wersjach 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 i 14.1.1.0.0 zawiera podatność Local File Inclusion która umożliwia nieuprawniony dostęp do danych."
    + UPDATE_HINT,
    "Fifteen WordPress themes are susceptible to code injection using a version of epsilon-framework, due to lack of capability and CSRF nonce checks in AJAX actions.": "Wykryto szablon WordPress umożliwiający zdalne wykonanie kodu ze względu na podatność w narzędziu epsilon-framework."
    + RCE_EFFECT_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "[no description] PHP Debug bar": "Wykryto narzędzie PHP Debug Bar, które umożliwia pobranie wrażliwych informacji, np. konfiguracji aplikacji. Rekomendujemy, aby to narzędzie nie było dostępne publicznie.",
    "The PHP Debug Bar tool was discovered, which allows the attacker to obtain sensitive information, e.g. application configuration.": "Wykryto narzędzie PHP Debug Bar, które umożliwia pobranie wrażliwych informacji, np. konfiguracji aplikacji. Rekomendujemy, aby to narzędzie nie było dostępne publicznie.",
    "The Django settings.py file containing a secret key was discovered. An attacker may use the secret key to bypass many security mechanisms and potentially obtain other sensitive configuration information such as database password) from the settings file.": "Wykryto plik z konfiguracją frameworku Django w którym znajduje się zmienna SECRET_KEY której poznanie umożliwi atakującemu ominięcie niektórych mechanizmów bezpieczeństwa Django. W tym pliku mogą też znajdować się inne wrażliwe dane, takie jak np. hasła do bazy danych."
    + DATA_HIDE_HINT,
    "woocommerce-gutenberg-products-block is a feature plugin for WooCommerce Gutenberg Blocks. An SQL injection vulnerability impacts all WooCommerce sites running the WooCommerce Blocks feature plugin between version 2.5.0 and prior to version 2.5.16. Via a carefully crafted URL, an exploit can be executed against the `wc/store/products/collection-data?calculate_attribute_counts[][taxonomy]` endpoint that allows the execution of a read only sql query. There are patches for many versions of this package, starting with version 2.5.16. There are no known workarounds aside from upgrading.": "Wtyczka WordPress o nazwie woocommerce-gutenberg-products-block w wersjach pomiędzy 2.5.0 i 2.5.16 zawiera podatność SQL Injection, umożliwiającą odczyt dowolnych danych z bazy danych."
    + WORDPRESS_UPDATE_HINT,
    "Kanboard contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.": "Wykryto, że domyślne dane logowania do narzędzia Kanboard umożliwiają logowanie. Atakujący może uzyskać dostęp do kont użytkowników i pobrać wrażliwe dane, modyfikować dane lub uruchomić nieuprawnione operacje."
    + DEFAULT_CREDENTIALS_HINT,
    "BackupBuddy versions 8.5.8.0 - 8.7.4.1 are vulnerable to a local file inclusion vulnerability via the 'download' and 'local-destination-id' parameters.": "Narzędzie BackupBuddy w wersjach 8.5.8.0 - 8.7.4.1 zawiera podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "Synacor Zimbra Collaboration Suite 8.7.x before 8.7.11p10 has an XML external entity injection (XXE) vulnerability via the mailboxd component.": "Narzędzie Synacor Zimbra Collaboration Suite w wersjach 8.7.x poniżej 8.7.11p10 zawiera podatność XML external entity injection (XXE) która może umożliwić odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "NexusQA NexusDB before 4.50.23 allows the reading of files via ../ directory traversal and local file inclusion.": "Narzędzie NexusQA NexusDB w wersji poniżej 4.50.23 zawiera podatność Local File Inclusion, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "Windows is vulnerable to local file inclusion because of searches for /windows/win.ini on passed URLs.": "Wykryto podatność Local File Inclusion na serwerze Windows umożliwiającą odczyt dowolnych plików z serwera."
    + BUG_FIX_HINT,
    "Suprema BioStar before 2.8.2 Video Extension allows remote attackers can read arbitrary files from the server via local file inclusion.": "Rozszerzenie Video Extension narzędzia Suprema BioStar w wersji poniżej 2.8.2 zawiera podatność Local File Inclusion, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "Crystal Live HTTP Server 6.01 is vulnerable to local file inclusion.": "Narzędzie Crystal Live HTTP Server w wersji 6.01 zawiera podatność Local File Inclusion, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    'Barco Control Room Management through Suite 2.9 Build 0275 is vulnerable to local file inclusion that could allow attackers to access sensitive information and components. Requests must begin with the "GET /..\\.." substring.': "Narzędzie Barco Control Room Management w wersjach do Suite 2.9 Build 0275 zawiera podatność Local File Inclusion umożliwiającą dostęp do wrażliwych informacji."
    + UPDATE_HINT,
    "Acrolinx Server prior to 5.2.5 suffers from a local file inclusion vulnerability.": "Narzędzie Acrolinx Server w wersjach poniżej 5.2.5 zawiera podatność Local File Inclusion, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "Spring Data Commons, versions prior to 1.13 to 1.13.10, 2.0 to 2.0.5,\nand older unsupported versions, contain a property binder vulnerability\ncaused by improper neutralization of special elements.\nAn unauthenticated remote malicious user (or attacker) can supply\nspecially crafted request parameters against Spring Data REST backed HTTP resources\nor using Spring Data's projection-based request payload binding hat can lead to a remote code execution attack.": "Spring Data Commons w wersjach od 1.13 do 1.13.10, od 2.0 do 2.0.5 i starszych niewspieranych wersjach, zawiera podatność umożliwiającą zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "ThinkCMF  is susceptible to a remote code execution vulnerability.": "Wykryto, że narzędzie ThinkCMF umożliwia zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION,
    "ZZZCMS zzzphp V1.6.1 is vulnerable to remote code execution via the inc/zzz_template.php file because the parserIfLabel() function's filtering is not strict, resulting in PHP code execution as demonstrated by the if:assert substring.": "ZZZCMS zzzphp V1.6.1 umożliwia zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Xunyou CMS is vulnerable to local file inclusion. Attackers can use vulnerabilities to obtain sensitive information.": "Wykryto, że narzędzie Xunyou CMS zawiera podatność Local File Inclusion, umożliwiającą atakującemu odczyt wrażliwych informacji.",
    "Symfony 2.3.19 through 2.3.28, 2.4.9 through 2.4.10, 2.5.4 through 2.5.11, and 2.6.0 through 2.6.7, when ESI or SSI support enabled, does not check if the _controller attribute is set, which allows remote attackers to bypass URL signing and security rules by including 1) no hash or (2) an invalid hash in a request to /_fragment in the HttpKernel component.": "Symfony w wersji od 2.3.19 do 2.3.28, 2.4.9 do 2.4.10, 2.5.4 do 2.5.11 i 2.6.0 do 2.6.7 w niektórych sytuacjach umożliwia atakującemu ominięcie reguł bezpieczeństwa."
    + UPDATE_HINT,
    "Aviatrix Controller 6.x before 6.5-1804.1922 contains a vulnerability that allows unrestricted upload of a file with a dangerous type, which allows an unauthenticated user to execute arbitrary code via directory traversal.": "Aviatrix Controller w wersji 6.x poniżej 6.5-1804.1922 umożliwia zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "ECShop 2.x and 3.x contains a SQL injection vulnerability which can allow an attacker to inject arbitrary SQL statements via the referer header field and the dangerous eval function, thus possibly allowing an attacker to obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.": "ECShop 2.x i 3.x zawiera podatność SQL Injecton. Atakujący może pobrać wrażliwe informacje z bazy danych, zmodyfikować dane i wykonywać dowolne operacje administracyjne na podatnej stronie."
    + UPDATE_HINT,
    "The Member Hero WordPress plugin through 1.0.9 lacks authorization checks, and does not validate the a request parameter in an AJAX action, allowing unauthenticated users to call arbitrary PHP functions with no arguments.": "Wtyczka WordPress The Member Hero w wersjach do 1.0.9 umożliwia atakującym wykonywanie niektórych rodzajów nieuprawnionych operacji."
    + WORDPRESS_UPDATE_HINT,
    "WordPress Page Views Count plugin prior to 2.4.15 contains an unauthenticated SQL injection vulnerability.  It does not sanitise and escape the post_ids parameter before using it in a SQL statement via a REST endpoint. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.": "Wtyczka WordPress o nazwie Page Views Count w wersjach poniżej 2.4.15 zawiera podatność SQL Injection, która umożliwia atakującemu pobranie wrażliwych informacji z bazy danych, w tym danych osobowych czy haszy haseł."
    + WORDPRESS_UPDATE_HINT,
    "WordPress Modern Events Calendar Lite before 5.16.5 does not properly restrict access to the export files, allowing unauthenticated users to exports all events data in CSV or XML format.": "Wtyczka WordPress o nazwie Modern Events Calendar Lite w wersjach poniżej 5.6.15 umożliwia atakującemu pobranie informacji o wszystkich wydarzeniach."
    + WORDPRESS_CLOSED_PLUGIN_HINT,
    "WordPress Duplicator 1.3.24 & 1.3.26 are vulnerable to local file inclusion vulnerabilities that could allow attackers to download arbitrary files, such as the wp-config.php file. According to the vendor, the vulnerability was only in two\nversions v1.3.24 and v1.3.26, the vulnerability wasn't\npresent in versions 1.3.22 and before.": "Wtyczka WordPress o nazwie Duplicator w wersjach 1.3.24 i 1.3.26 zawiera podatność Local File Inclusion, umożliwiającą atakującemu odczyt wrażliwych informacji, w tym haseł dostępowych do bazy danych."
    + WORDPRESS_UPDATE_HINT,
    "It discloses sensitive files created by vscode-sftp for VSCode, contains SFTP/SSH server details and credentials.": "Wykryto plik .vscode/sftp.json mogący zawierać dane do logowania do serwera SSH/SFTP/FTP."
    + DATA_HIDE_HINT,
    "A SQL injection vulnerability in Joomla! 3.2 before 3.4.4 allows remote attackers to execute arbitrary SQL commands.": "Podatność SQL Injection w systemie Joomla! w wersjach od 3.2 poniżej 3.4.4 zezwala atakującym na wykonywanie dowolnych poleceń SQL."
    + UPDATE_HINT,
    "A Laravel .env file was discovered, which stores sensitive information like database credentials and tokens. It should not be publicly accessible.": "Wykryto plik .env zawierający konfigurację systemu. Ponieważ może on zawierać np. hasła, nie powinien być dostępny publicznie.",
    "Codeigniter .env file was discovered.": "Wykryto plik .env zawierający konfigurację systemu. Ponieważ może on zawierać np. hasła, nie powinien być dostępny publicznie.",
    "WordPress Modern Events Calendar plugin before 6.1.5 is susceptible to blind SQL injection. The plugin does not sanitize and escape the time parameter before using it in a SQL statement in the mec_load_single_page AJAX action. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.": "Wtyczka WordPress o nazwie Modern Events Calendar w wersjach poniżej 6.1.5 zawiera podatność Blind SQL Injection, umożliwiającą pobranie dowolnej informacji z bazy danych."
    + WORDPRESS_CLOSED_PLUGIN_HINT,
    "Agentejo Cockpit before 0.11.2 allows NoSQL injection via the Controller/Auth.php resetpassword function of the Auth controller.": "Narzędzie Agentejo Cockpit w wersji poniżej 0.11.2 zawiera podatność typu NoSQL Injection umożliwiającą zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "A directory traversal vulnerability in the Highslide JS (com_hsconfig) component 1.5 and 2.0.9 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the controller parameter to index.php.": "Wykryto podatność Directory Traversal w komponencie Highslide JS (com_hsconfig) systemu Joomla! w wersjach 1.5 i 2.0.9 umożliwiającą atakującym odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "Laravel Ignition contains a cross-site scripting vulnerability when debug mode is enabled.": "Narzędzie Laravel Ignition zawiera podatność Cross-Site Scripting jeśli tryb 'debug' jest włączony. Rekomendujemy wyłączenie tego trybu.",
    "SFTP configuration file was detected.": "Wykryto plik sftp-config.json lub ftpsync.settings zawierający dane logowania."
    + DATA_HIDE_HINT,
    "SFTP credentials were detected.": "Wykryto plik sftp-config.json lub ftpsync.settings zawierający dane logowania."
    + DATA_HIDE_HINT,
    "Nagios default admin credentials were discovered.": "Wykryto, że domyślne dane do logowania do narzędzia Nagios umożliwiają logowanie."
    + DEFAULT_CREDENTIALS_HINT,
    "This subdomain take over would only work on an edge case when the account was deleted. You will need a premium account (~ US$7) to test the take over.": "Wykryto domenę skonfigurowaną, aby serwować treści z narzędzia Wix, ale strona docelowa nie istnieje. Strona może być w niektórych przypadkach przejęta, jeśli konto w serwisie Wix zostało usunięte. Jeśli domena nie jest używana, rekomendujemy jej usunięcie.",
    "Jenkins Git plugin through 4.11.3 contains a missing authorization check. An attacker can trigger builds of jobs configured to use an attacker-specified Git repository and to cause them to check out an attacker-specified commit. This can make it possible to obtain sensitive information, modify data, and/or execute unauthorized operations.": "Wtyczka Jenkins Git Plugin w wersji 4.11.3 i wcześniejszych umożliwia atakującym nieuprawnione uruchamianie zadań."
    + UPDATE_HINT,
    "Magento Cacheleak is an implementation vulnerability, result of bad implementation of web-server configuration for Magento platform. Magento was developed to work under the Apache web-server which natively works with .htaccess files, so all needed configuration directives specific for various internal Magento folders were placed in .htaccess files.  When Magento is installed on web servers that are ignoring .htaccess files such as nginx an attacker can get access to internal Magento folders (such as the Magento cache directory) and extract sensitive information from cache files.": "Wykryto podatność Magento Cacheleak: gdy narzędzie Magento jest zainstalowane na serwerze HTTP niewspierającym plików .htaccess, to zabezpieczenia zapewniane przez pliki .htaccess są wyłączone, co umożliwia atakującemu dostęp do wewnętrznych folderów Magento i np. pobranie wrażliwych danych z pamięci podręcznej. Rekomendujemy zmianę konfiguracji systemu tak, aby takie dane nie były dostępne publicznie.",
    "PHP Proxy 3.0.3 is susceptible to local file inclusion vulnerabilities that allow unauthenticated users to read files from the server via index.php?q=file:/// (a different vulnerability than CVE-2018-19246).": "Narzędzie PHP Proxy w wersji 3.0.3 zawiera podatność Local File Inclusion umożliwiającą atakującym odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "Solr's admin page was able to be accessed with no authentication requirements in place.": "Panel administracyjny narzędzia Solr jest dostępny bez logowania. Rekomendujemy włączenie uwierzytelniania.",
    "Apache Solr versions prior to and including 8.8.1 are vulnerable to local file inclusion.": "Apache Solr w wersji 8.8.1 i wcześniejszych zawiera podatność Local File Inclusion umożliwiającą atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "Ntopng, a passive network monitoring tool, contains an authentication bypass vulnerability in ntopng <= 4.2": "Narzędzie Ntopng w wersji 4.2 i wcześniejszych zawiera podatność umożliwiającą ominięcie autoryzacji."
    + UPDATE_HINT,
    "The log file of this Laravel web app might reveal details on the inner workings of the app, possibly even tokens, credentials or personal information.": "Wykryto dostępny publicznie dziennik zdarzeń systemu Laravel, który może zawierać informacje o działaniu aplikacji, dane osobowe, dane uwierzytelniające lub inne rodzaje wrażliwych danych."
    + DATA_HIDE_HINT,
    "Programs run on GeoServer before 1.2.2 which use jt-jiffle and allow Jiffle script to be provided via network request are susceptible to remote code execution. The Jiffle script is compiled into Java code via Janino, and executed. In particular, this affects downstream GeoServer 1.1.22.": "Programy uruchamiane w narzędziu GeoServer w wersji poniżej 1.2.2 korzystające z narzędzia jt-jiffle i umożliwiające korzystanie ze skryptów Jiffle przesyłanych w żądaniu sieciowym umożliwiają atakującym zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Parameters.yml was discovered.": "Wykryto plik parameters.yml zawierający dane dostępowe do bazy danych."
    + DATA_HIDE_HINT,
    "OpenSNS allows remote unauthenticated attackers to execute arbitrary code via the 'shareBox' endpoint.": 'Wykryto, że narzędzie OpenSNS umożliwia zdalne wykonanie kodu poprzez zasób "shareBox".'
    + RCE_EFFECT_DESCRIPTION,
    'A vulnerability exists in Thinfinity VirtualUI in a function located in /lab.html reachable which by default  could allow IFRAME injection via the "vpath" parameter.': "Wykryto, że narzędzie Thinkfinity VirtualUI zawiera podatność umożliwiającą wyświetlenie ramki iframe zawierającej dowolną stronę internetową.",
    "Odoo database manager was discovered.": "Wykryto publicznie dostępny system do zarządzania bazą danych systemu Odoo. Rekomendujemy, aby takie zasoby nie były dostępne publicznie.",
    "A Symfony installations 'debug' interface is enabled, allowing the disclosure and possible execution of arbitrary code.": "Wykryto narzędzie Symfony w konfiguracji debug. Udostępnienie narzędzia z tą opcją może prowadzić np. do wycieku kodu aplikacji lub możliwości zdalnego wykonania kodu. Rekomendujemy, aby taka konfiguracja nie była dostępna publicznie."
    + RCE_EFFECT_DESCRIPTION,
    "Private SSL, SSH, TLS, and JWT keys were detected.": "Wykryto klucze prywatne SSL, SSH, TLS lub JWT."
    + DATA_HIDE_HINT,
    "WordPress Site Editor through 1.1.1 allows remote attackers to retrieve arbitrary files via the ajax_path parameter to editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php.": "Wtyczka WordPress o nazwie WordPress Site Editor w wersjach do 1.1.1 zezwala atakującym na pobieranie dowolnych plików z serwera."
    + WORDPRESS_UPDATE_HINT,
    "MCMS 5.2.5 contains a SQL injection vulnerability via the categoryId parameter in the file IContentDao.xml. An attacker can potentially obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.": "MCMS w wersji 5.2.5 zawiera podatność SQL Injection. Atakujący może pobrać wrażliwe informacje z bazy danych, zmodyfikować dane i wykonywać dowolne operacje administracyjne na podatnej stronie."
    + UPDATE_HINT,
    "Adminer before 4.7.9 is susceptible to server-side request forgery due to exposure of sensitive information in error messages. Users of Adminer versions bundling all drivers, e.g. adminer.php, are affected. An attacker can possibly obtain this information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.": "Narzędzie Adminer w wersji poniżej 4.7.9 zawiera podatność Server-Side Request Forgery. Może to umożliwić atakującemu komunikację z usługami w sieci wewnętrznej, a w niektórych konfiguracjach również uzyskanie nieuprawnionego dostępu do systemu."
    + UPDATE_HINT,
    "WordPress Fusion Builder plugin before 3.6.2 is susceptible to server-side request forgery. The plugin does not validate a parameter in its forms, which can be used to initiate arbitrary HTTP requests. The data returned is then reflected back in the application's response. An attacker can potentially interact with hosts on the server's local network, bypass firewalls, and access control measures.": "Wtyczka WordPress o nazwie Fusion Builder w wersji poniżej 3.6.2 zawiera podatność Server-Side Request Forgery. Może to umożliwić atakującemu komunikację z usługami w sieci wewnętrznej, a w niektórych konfiguracjach również uzyskanie nieuprawnionego dostępu do systemu."
    + WORDPRESS_UPDATE_HINT,
    "WordPress Metform plugin through 2.1.3 is susceptible to information disclosure due to improper access control in the ~/core/forms/action.php file. An attacker can view all API keys and secrets of integrated third-party APIs such as that of PayPal, Stripe, Mailchimp, Hubspot, HelpScout, reCAPTCHA and many more.": "Wtyczka WordPress o nazwie Metform w wersjach do 2.1.3 umożliwia atakującemu pobranie kluczy API usług takich jak PayPal, Stripe, Mailchimp, Hubspot, HelpScout czy reCAPTCHA."
    + WORDPRESS_UPDATE_HINT,
    "[no description] vulnerabilities/generic/cache-poisoning-xss.yaml": "Wykryto podatność Cache Poisoning, umożliwiającą atakującemu zmianę treści prezentowanych innym użytkownikom serwisu, w tym umieszczenie tam szkodliwego oprogramowania."
    + BUG_FIX_HINT,
    "Apache Tomcat Manager default login credentials were discovered. This template checks for multiple variations.": "Wykryto, że domyślne dane logowania do narzędzia Apache Tomcat Manager umożliwiają logowanie."
    + DEFAULT_CREDENTIALS_HINT,
    "Joomla! Component GMapFP 3.5 is vulnerable to arbitrary file upload vulnerabilities. An attacker can access the upload function of the application\nwithout authentication and can upload files because of unrestricted file upload which can be bypassed by changing Content-Type & name file too double ext.": "Komponent Joomla! o nazwie GMapFP w wersji 3.5 umożliwia atakującemu umieszczanie w systemie plików dowolnego typu, a w konsekwencji wykonanie dowolnego kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "WordPresss acf-to-rest-ap through 3.1.0 allows an insecure direct object reference via permalinks manipulation, as demonstrated by a wp-json/acf/v3/options/ request that can read sensitive information in the wp_options table such as the login and pass values.": "Wtyczka WordPress o nazwie acf-to-rest-ap w wersji do 3.1.0 zawiera podatność Insecure Direct Object Reference, która umożliwia odczyt wrażliwych informacji konfiguracyjnych z serwisu."
    + WORDPRESS_UPDATE_HINT,
    "Jolokia agent is vulnerable to a JNDI injection vulnerability that allows a remote attacker to run arbitrary Java code on the server when the agent is in proxy mode.": "Wykryto konfigurację narzędzia Jolokia która umożliwia atakującemu wykonanie dowolnego kodu."
    + RCE_EFFECT_DESCRIPTION,
    "WEMS Enterprise Manager contains a cross-site scripting vulnerability via the /guest/users/forgotten endpoint and the email parameter, which allows a remote attacker to inject arbitrary JavaScript into the response return by the server.": "Narzędzie WEMS Enterprise Manager zawiera podatność typu Cross-Site Scripting, umożliwiającą atakującemu wstrzykiwanie dowolnych skryptów do odpowiedzi serwera."
    + UPDATE_HINT,
    "Blackboard contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Narzędzie Blackboard zawiera podatność typu Cross-Site Scripting, umożliwiającą atakującemu spreparowanie linku, który - kliknięty przez użytkownika - wykona dowolną akcję z jego uprawnieniami."
    + UPDATE_HINT,
    "Sickbeard contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Narzędzie Sickbeard zawiera podatność typu Cross-Site Scripting, umożliwiającą atakującemu spreparowanie linku, który - kliknięty przez użytkownika - wykona dowolną akcję z jego uprawnieniami."
    + UPDATE_HINT,
    "JavaMelody contains a cross-site scripting vulnerability via the monitoring parameter. An attacker can execute arbitrary script in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Narzędzie JavaMelody zawiera podatność typu Cross-Site Scripting, umożliwiającą atakującemu spreparowanie linku, który - kliknięty przez użytkownika - wykona dowolną akcję z jego uprawnieniami."
    + UPDATE_HINT,
    "Discourse contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.": "Narzędzie Discourse zawiera podatność typu Cross-Site Scripting, umożliwiającą atakującemu spreparowanie linku, który - kliknięty przez użytkownika - wykona dowolną akcję z jego uprawnieniami."
    + UPDATE_HINT,
    "Drone configuration was discovered.": "Wykryto konfigurację narzędzia Drone." + DATA_HIDE_HINT,
    "Seagate NAS OS version 4.3.15.1 has insufficient access control which allows attackers to obtain information about the NAS without authentication via empty POST requests in /api/external/7.0/system.System.get_infos.": "Seagate NAS OS w wersji 4.3.15.1 zawiera niewystarczające mechanizmy kontroli dostępu, co umożliwia atakującemu nieuprawnione uzyskanie informacji o systemie."
    + UPDATE_HINT,
    "Geoserver default admin credentials were discovered.": "Wykryto, że domyślne dane do logowania do narzędzia Geoserver umożliwiają logowanie."
    + DEFAULT_CREDENTIALS_HINT,
    "[no description] http/vulnerabilities/wordpress/wp-config-setup.yaml": "Wykryto plik instalacyjny /wp-admin/setup-config.php, umożliwiający instalację systemu WordPress. Udostępnienie takiego panelu umożliwi atakującemu wykonanie dowolnego kodu na serwerze. Rekomendujemy, aby takie zasoby nie były dostępne publicznie.",
    "Some Dahua products contain an authentication bypass during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.": "Wykryto produkt Dahua zawierający możiwość ominięcia uwierzytelniania.",
    "SAP xMII 15.0 for SAP NetWeaver 7.4 is susceptible to a local file inclusion vulnerability in the GetFileList function. This can allow remote attackers to read arbitrary files via a .. dot dot) in the path parameter to /Catalog, aka SAP Security Note 2230978.": "Narzędzie SAP xMII 15.0 dla SAP NetWeaver 7.4 zawiera podatność Local File Inclusion, umożliwiającą atakującym pobranie dowolnego pliku z serwera.",
    'Revive Adserver 4.2 is susceptible to remote code execution. An attacker can send a crafted payload to the XML-RPC invocation script and trigger the unserialize) call on the "what" parameter in the "openads.spc" RPC method. This can be exploited to perform various types of attacks, e.g. serialize-related PHP vulnerabilities or PHP object injection. It is possible, although unconfirmed, that the vulnerability has been used by some attackers in order to gain access to some Revive Adserver instances and deliver malware through them to third-party websites.': "Narzędzie Revive Adserver w wersji 4.2 zawiera podatność typu Remote Code Execution."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "A .env file was discovered containing sensitive information like database credentials and tokens. It should not be publicly accessible.": "Wykryto plik .env zawierający wrażliwe informacje takie jak dane dostępowe do bazy danych lub klucze API. Takie pliki nie powinny być dostępne publicznie.",
    "[no description] http/takeovers/tilda-takeover.yaml": "Wykryto domenę kierującą do narzędzia Tilda, ale domena docelowa jest wolna. Atakujący może zarejestrować domenę w narzędziu Tilda, aby serwować tam swoje treści.",
    "[no description] http/misconfiguration/clockwork-dashboard-exposure.yaml": "Wykryto publicznie dostępny panel narzędzia Clockwork. Rekomendujemy, aby takie zasoby nie były dostępne publicznie.",
    "[no description] http/vulnerabilities/generic/cache-poisoning-xss.yaml": "Wykryto podatność Cache Poisoning, umożliwiającą atakującemu zmianę treści prezentowanych innym użytkownikom serwisu, w tym umieszczenie tam szkodliwego oprogramowania."
    + BUG_FIX_HINT,
    "The Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services) versions 0.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0 contain an easily exploitable vulnerability that allows unauthenticated attackers with network access via HTTP to compromise Oracle WebLogic Server.": "Komponent Oracle WebLogic Server narzędzia Oracle Fusion Middleware w wersji 0.3.6.0.0, 12.1.3.0.0 i 12.2.1.3.0 zawiera podatność umożliwiającą zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "GLPI through 10.0.2 is susceptible to remote command execution injection in /vendor/htmlawed/htmlawed/htmLawedTest.php in the htmlawed module.": "Narzędzie GLPI w wersji do 10.0.2 włącznie umożliwia zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Anonymous user access allows to understand the host internals": "Wykryto, że anonimowy użytkownik może uzyskać dostęp do narzędzia Glowroot. Rekomendujemy zmianę tej konfiguracji.",
    "WordPress Advanced Access Manager versions before 5.9.9 are vulnerable to local file inclusion and allows attackers to download the wp-config.php file and get access to the database, which is publicly reachable on many servers.": "Wtyczka WordPress o nazwie Advanced Access Manager w wersji poniżej 5.9.9 zawiera podatność Local File Inclusion, umożliwiającą odczyt dowolnych plików z serwera."
    + WORDPRESS_UPDATE_HINT,
    "CRLF sequences were not properly sanitized.": "Wykryto podatność CRLF Injection. Za jej pomocą atakujący może m.in. spreparować link, który - gdy kliknięty przez administratora - wykona dowolną operację na stronie którą może wykonać administrator (taką jak np. modyfikację treści)."
    + BUG_FIX_HINT,
    "A cross-site scripting vulnerability was discovered via generic testing. Manual testing is needed to verify exploitation.": "Wykryto podatność Cross-Site Scripting. Za jej pomocą atakujący może m.in. spreparować link, który - gdy kliknięty przez administratora - wykona dowolną operację na stronie którą może wykonać administrator (taką jak np. modyfikację treści)."
    + BUG_FIX_HINT,
    "JexBoss is susceptible to remote code execution via the webshell. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.": "Wykryto, że narzędzie JexBoss zawiera podatność umożliwiającą zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION,
    "OpenAM contains an LDAP injection vulnerability. When a user tries to reset his password, they are asked to enter username, and then the backend validates whether the user exists or not through an LDAP query. If the user exists, the password reset token is sent to the user's email. Enumeration can allow for full password retrieval.": "Narzędzie OpenAM zawiera podatność LDAP Injection, umożliwiającą poznanie pełnego hasła użytkownika."
    + UPDATE_HINT,
    "ForgeRock AM server before 7.0 has a Java deserialization vulnerability in the jato.pageSession parameter on multiple pages.\nThe exploitation does not require authentication, and remote code execution can be triggered by sending a single crafted\n/ccversion/* request to the server. The vulnerability exists due to the usage of Sun ONE Application Framework (JATO)\nfound in versions of Java 8 or earlier.": "Serwer ForgeRock AM w wersji poniżej 7.0 zawiera podatnosć umożliwiającą zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Joomla! CMS 3.0.0 through the 3.4.6 release contains an unauthenticated PHP object injection that leads to remote code execution.": "System Joomla w wersji od 3.0.0 do 3.4.6 zawiera podatność PHP Object Injection, która może doprowadzić do zdalnego wykonania kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Openfire is an XMPP server licensed under the Open Source Apache License. Openfire's administrative console, a web-based application, was found to be vulnerable to a path traversal attack via the setup environment. This permitted an unauthenticated user to use the unauthenticated Openfire Setup Environment in an already configured Openfire environment to access restricted pages in the Openfire Admin Console reserved for administrative users. This vulnerability affects all versions of Openfire that have been released since April 2015, starting with version 3.10.0.": "Wykryto, że narzędzie Openfire zawiera podatność Path Traversal, umożliwiającą nieuprawniony dostęp do podstron zarezerwowanych dla administratorów."
    + UPDATE_HINT,
    "[no description] http/misconfiguration/installer/owncloud-installer-exposure.yaml": "Wykryto, że instalator narzędzia ownCloud jest publicznie dostępny, co umożliwia atakującemu rejestrację jako administrator. Rekomendujemy, aby takie zasoby nie były publicznie dostępne.",
    "Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.3 to 5.6.7 and 5.4.6 to 5.4.12 and FortiProxy 2.0.0, 1.2.0 to 1.2.8, 1.1.0 to 1.1.6, 1.0.0 to 1.0.7 under SSL VPN web portal allows an unauthenticated attacker to download system files via special crafted HTTP resource requests due to improper limitation of a pathname to a restricted directory (path traversal).": "System Fortinet FortiOS w wersji od 6.0.0 do 6.0.4, od 5.6.3 do 5.6.7 oraz od 5.4.6 do 5.4.12 a także narzędzie FortiProxy 2.0.0, od 1.2.0 do 1.2.8, od 1.1.0 do 1.1.6 oraz od 1.0.0 do 1.0.7 umożliwia atakującemu pobieranie dowolnych plików systemowych."
    + UPDATE_HINT,
    'Revive Adserver 4.2 is susceptible to remote code execution. An attacker can send a crafted payload to the XML-RPC invocation script and trigger the unserialize() call on the "what" parameter in the "openads.spc" RPC method. This can be exploited to perform various types of attacks, e.g. serialize-related PHP vulnerabilities or PHP object injection. It is possible, although unconfirmed, that the vulnerability has been used by some attackers in order to gain access to some Revive Adserver instances and deliver malware through them to third-party websites.': "Narzędzie Revive Adserver w wersji 4.2 umożliwia zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Check for remote code execution via OpenCPU was conducted.": "Wykryto, że narzędzie OpenCPU umożliwia zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION,
    "WordPress Simple Link Directory plugin before 7.7.2 contains a SQL injection vulnerability. The plugin does not validate and escape the post_id parameter before using it in a SQL statement via the qcopd_upvote_action AJAX action, available to unauthenticated and authenticated users. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.": "Wtyczka WordPress o nazwie Simple Link Directory w wersji poniżej 7.7.2 zawiera podatność SQL Injection, umożliwiającą atakującemu pobranie całej zawartości bazy danych."
    + UPDATE_HINT,
    "WordPress Woody Ad Snippets prior to 2.2.5 is susceptible to cross-site scripting and remote code execution via admin/includes/class.import.snippet.php, which allows unauthenticated options import as demonstrated by storing a cross-site scripting payload for remote code execution.": "Wtyczka WordPress o nazwie Woody Ad Snippets w wersji poniżej 2.2.5 zawiera podatność Cross-Site Scripting a także umożliwia zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "SSHv1 is deprecated and has known cryptographic issues.": "Wykryto protokół SSHv1, który jest przestarzały i podatny na znane ataki."
    + UPDATE_HINT,
    "[no description] http/exposures/logs/roundcube-log-disclosure.yaml": "Wykryto dziennik zdarzeń systemu Roundcube. Może on zawierać takie dane jak np. informacje o nadawcach i odbiorcach e-maili czy informacje o konfiguracji systemu."
    + DATA_HIDE_HINT,
    "[no description] http/takeovers/netlify-takeover.yaml": "Domena jest skonfigurowana, aby serwować treści z narzędzia Netlify, ale domena docelowa jest wolna. Atakujący może potencjalnie zarejestrować taką domenę w serwisie Netlify aby umieścić tam swoje treści. Jeśli domena jest nieużywana, rekomendujemy jej usunięcie.",
    "WordPress Zoomsounds plugin 6.45 and earlier allows arbitrary files, including sensitive configuration files such as wp-config.php, to be downloaded via the `dzsap_download` action using directory traversal in the `link` parameter.": "Wtyczka WordPress o nazwie Zoomsounds w wersji 6.45 i wcześniejszych umożliwia atakującemu pobieranie dowolnych plików z serwera, w tym plików konfiguracyjnych."
    + UPDATE_HINT,
    "phpMyAdmin panel was detected.": "wykryto panel logowania narzędzia phpMyAdmin.",
    "WordPress login panel was detected.": "wykryto panel logowania systemu WordPress.",
    "phpPgAdmin login ipanel was detected.": "wykryto panel logowania narzędzia phpPgAdmin.",
    "[no description] http/exposed-panels/tomcat/tomcat-exposed-docs.yaml": "wykryto dokumentację Apache Tomcat.",
    "An Adminer login panel was detected.": "wykryto panel logowania narzędzia Adminer.",
    "Webalizer panel was detected.": "wykryto panel narzędzia Webalizer.",
    "FortiOS admin login panel was detected.": "wykryto panel logowania do panelu administracyjnego narzędzia FortiOS.",
    "Fortinet FortiGate SSL VPN login panel was detected.": "wykryto panel logowania Fortinet FortiGate SSL VPN.",
    "Plesk Obsidian login panel was detected.": "wykryto panel logowania narzędzia Plesk Obsidian.",
    "Contao login panel was detected.": "wykryto panel logowania narzędzia Contao.",
    "TYPO3 login panel was detected.": "wykryto panel logowania narzędzia TYPO3.",
    "GeoServer login panel was detected.": "wykryto panel logowania narzędzia GeoServer",
    "Zimbra Collaboration Suite panel was detected. Zimbra Collaboration Suite simplifies the communication environment, connects people over multiple channels, and provides a single place to manage collaboration and communication.": "wykryto panel logowania narzędzia Zimbra Collaboration Suite.",
    "Craft CMS admin login panel was detected.": "wykryto panel administracyjny narzędzia Craft CMS.",
    "phpMiniAdmin login panel was detected.": "wykryto panel logowania phpMiniAdmin.",
    "Pagespeed Global Admin panel was detected.": "wykryto panel administracyjny narzędzia Pagespeed Global",
    "Nginx Proxy Manager login panel was detected.": "wykryto panel logowania narzędzia Nginx Proxy Manager.",
    "QNAP Photo Station panel was detected.": "wykryto panel narzędzia QNAP Photo Station.",
    "Fortinet FortiOS Management interface panel was detected.": "wykryto panel administracyjny narzędzia Fortinet FortiOS.",
    "Webmin admin login panel was detected.": "wykryto panel administracyjny narzędzia Webmin.",
    "Internet Multi Server Control Panel was detected.": "wykryto panel administracyjny narzędzia Internet Multi Server.",
    "Microsoft Exchange Admin Center login panel was detected.": "wykryto panel logowania narzędzia Microsoft Exchange Admin Center.",
    "Apache Tomcat Manager login panel was detected.": "wykryto panel logowania narzędzia Apache Tomcat Manager.",
    "Checkpoint login panel was detected.": "wykryto panel logowania narzędzia Checkpoint.",
    "Pulse Secure VPN login panel was detected.": "wykryto panel logowania Pulse Secure VPN.",
    "Retool login panel was detected.": "wykryto panel logowania narzędzia Retool.",
    "Oracle WebLogic UDDI Explorer panel was detected.": "wykryto panel narzędzia Oracle WebLogic UDDI Explorer.",
    "An ArcGIS instance was discovered.": "wykryto narzędzie ArcGIS.",
    "An ActiveAdmin Admin dashboard was discovered.": "wykryto panel administracyjny narzędzia ActiveAdmin.",
    "TeamCity login panel was detected.": "wykryto panel logowania narzędzia TeamCity.",
    "GNU Mailman panel was detected. Panel exposes all public mailing lists on server.": "wykryto panel narzędzia GNU Mailman.",
    "Jupyter Notebook login panel was detected.": "wykryto panel logowania narzędzia Jupyter Notebook.",
    "Nagios login panel was detected.": "wykryto panel logowania narzędzia Nagios.",
    "Roxy File Manager panel was detected.": "wykryto panel narzędzia Roxy File Manager.",
    "QNAP QTS login panel was detected.": "wykryto panel logowania narzędzia QNAP QTS.",
    "GLPI panel was detected.": "wykryto panel GLPI.",
    "Cacti login panel was detected.": "wykryto panel logowania Cacti.",
    "Keycloak admin login panel was detected.": "wykryto panel logowania narzędzia Keycloak.",
    "Redis Commander panel was detected.": "wykryto panel narzędzia Redis Commander.",
    "VMware Horizon login panel was detected.": "wykryto panel logowania narzędzia VMware Horizon.",
    "Watchguard login panel was detected.": "wykryto panel logowania Watchguard.",
    "Fireware XTM login panel was detected.": "wykryto panel logowania Fireware XTM.",
    "MailWatch login panel was detected.": "wykryto panel logowania MailWatch.",
    "WampServer panel was detected.": "wykryto panel WampServer.",
    "Gitea login panel was detected.": "wykryto panel Gitea.",
    "Monitorix panel was detected.": "wykryto panel Monitorix.",
    "Fortinet FortiMail login panel was detected.": "wykryto panel logowania Fortinet FortiMail.",
    "osTicket login panel was detected.": "wykryto panel logowania osTicket.",
    "Gitlab login panel was detected.": "wykryto panel logowania GitLab.",
    "FastAPI Docs panel was detected.": "wykryto dokumentację FastAPI.",
    "UniFi Network login panel was detected.": "wykryto panel logowania UniFi Network.",
    "Sophos Firewall login panel was detected.": "wykryto panel logowania Sophos Firewall.",
    "Matomo logjn panel was detected.": "wykryto panel logowania Matomo.",
    "Modoboa login panel was detected.": "wykryto panel logowania narzędia Modoboa.",
    "QmailAdmin login panel was detected.": "wykryto panel logowania QmailAdmin.",
    "Jenkins is an open source automation server.": "wykryto panel logowania systemu Jenkins.",
    "Plesk Onyx login panel was detected.": "wykryto panel logowania Plesk Onyx.",
    "Gogs login panel was detected.": "wykryto panel logowania Gogs.",
    "WildFly welcome page was detected.": "Wykryto stronę startową WildFly.",
    "Grafana login panel was detected.": "Wykryto panel logowania narzędzia Grafana.",
    "Web Service panel was detected.": "Wykryto panel narzędzia Web Service.",
    "DirectAdmin login panel was detected.": "wykryto panel narzędzia DirectAdmin.",
}
