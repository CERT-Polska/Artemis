# This is not a .po file because we want to build the translation results from parts - for example,
# glue a generic message describing what a RCE leads to to some messages.

RCE_EFFECT_DESCRIPTION = (
    " Korzystając z tej podatności, atakujący może wykonać dowolne polecenie systemowe i dzięki temu pobrać dane z systemu, "
    "zmodyfikować je lub w dowolny sposób zmienić zachowanie systemu."
)

WORDPRESS_UPDATE_HINT = (
    " Rekomendujemy aktualizację i włączenie automatycznej aktualizacji systemu WordPress, wtyczek i szablonów."
)

WORDPRESS_CLOSED_PLUGIN_HINT = "Ponieważ ta wtyczka nie jest już wspierana, rekomendujemy jej usunięcie."

PLUGIN_UPDATE_HINT = " Rekomendujemy aktualizację wtyczki do najnowszej wersji."

UPDATE_HINT = " Rekomendujemy aktualizację oprogramowania do najnowszej wersji."

DEFAULT_CREDENTIALS_HINT = " Rekomendujemy zmianę domyślnych haseł."

BUG_FIX_HINT = " Rekomendujemy poprawienie tego błędu, a także sprawdzenie, czy podobne błędy nie występują również w innych miejscach systemu."

DATA_HIDE_HINT = " Rekomendujemy, aby takie dane nie były dostępne publicznie."

REFLECTED_XSS_DESCRIPTION = "Cross-Site Scripting, umożliwiającą atakującemu spreparowanie linku, który, po kliknięciu przez administratora, wykona dowolną akcję z jego uprawnieniami (taką jak np. modyfikacja treści)."

DIRECTORY_INDEX_HINT = "Taka konfiguracja może w niektórych przypadkach stworzyć ryzyko wycieku wrażliwych danych. Nawet jeśli w podanych wyżej folderach nie ma wrażliwych danych, zaobserwowana konfiguracja może oznaczać, że serwer wyświetla listingi również innych katalogów. Jeśli nie jest to działanie celowe, to rekomendujemy konfigurację serwera tak, aby listing plików nie był publicznie dostępny."

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
    "GitLab CE/EE is susceptible to information disclosure. An attacker can access runner registration tokens using quick actions commands, thereby making it possible to obtain sensitive information, modify data, and/or execute unauthorized operations. Affected versions are from 12.10 before 14.6.5, from 14.7 before 14.7.4, and from 14.8 before 14.8.2.": "W narzędziu GitLab CE/EE w wersjach od 12.10 poniżej 14.6.5, od 14.7 poniżej 14.7.4 i od 14.8 poniżej 14.8.2 znaleziono podatność umożliwiającą pobieranie danych umożliwiających rejestrację dodatkowych maszyn wykonujących zadania CI, a w konsekwencji np. pobranie kodu źródłowego czy danych uwierzytelniających udostępnianych na potrzeby zadań CI."
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
    "Zabbix default admin credentials were discovered.": "Wykryto, że możliwe jest logowanie do systemu Zabbix za pomocą domyślnych danych. Atakujący może pobrać wrażliwe dane, modyfikować ustawienia lub uruchomić nieuprawnione operacje."
    + DEFAULT_CREDENTIALS_HINT,
    "WordPress Statistic plugin versions prior to version 13.0.8 are affected by an unauthenticated time-based blind SQL injection vulnerability.": "Wersje wtyczki WordPress Statistics poniżej 13.0.8 zawierają podatność Time-based Blind SQL Injection, która umożliwia pobranie dowolnej informacji z bazy danych."
    + WORDPRESS_UPDATE_HINT,
    "ClamAV server 0.99.2, and possibly other previous versions, allow the execution\nof dangerous service commands without authentication. Specifically, the command 'SCAN'\nmay be used to list system files and the command 'SHUTDOWN' shut downs the service.": "Serwer ClamAV w wersji 0.99.2 (możliwe jest, że również w niektórych wcześniejszych wersjach) umożliwia uruchamianie niebezpiecznych komend bez uwierzytelnienia, co może skutkować np. pobraniem listy plików na serwerze lub wyłączeniem usługi."
    + UPDATE_HINT,
    "MAGMI (Magento Mass Importer) is vulnerable to cross-site request forgery (CSRF) due to a lack of CSRF tokens. Remote code execution (via phpcli command) is also possible in the event that CSRF is leveraged against an existing admin session.": "Wykryto, że narzędzie MAGMI (Magento Mass Importer) zawiera podatność Cross-Site Request Forgery, co może potencjalnie prowadzić do zdalnego wykonania kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "group:sql-injection": "Wykryto podatność SQL Injection na podstawie komunikatu o błędzie. Ta podatność może umożliwiać pobranie dowolnej informacji z bazy danych."
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
    "OEcms 3.1 is vulnerable to reflected cross-site scripting via the mod parameter of info.php.": "OEcms w wersji 3.1 i potencjalnie wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "LabKey Server Community Edition before 18.3.0-61806.763 contains a reflected cross-site scripting vulnerability via the onerror parameter in the /__r2/query endpoints, which allows an unauthenticated remote attacker to inject arbitrary JavaScript.": "LabKey Server Community Edition w wersji poniżej 18.3.0-61806.763 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Symfony profiler was detected.": "Wykryto narzędzie Symfony Profiler. Udostępnienie tego narzędzia może prowadzić np. do wycieku konfiguracji aplikacji (w tym haseł do bazy danych), kodu źródłowego lub innych informacji, które nie powinny być dostępne publicznie. Rekomendujemy, aby to narzędzie nie było dostępne publicznie.",
    "Flir is vulnerable to local file inclusion.": "Narzędzie Flir zawiera podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików z serwera.",
    "IPConfigure Orchid Core VMS 2.0.5 is susceptible to local file inclusion.": "IPConfigure Orchid Core VMS w wersji 2.0.5 i potencjalnie wcześniejszych zawiera podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików z serwera.",
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
    "The Oracle Access Manager  portion of Oracle Fusion Middleware (component: OpenSSO Agent) is vulnerable to remote code execution. Supported versions that are affected are 11.1.2.3.0, 12.2.1.3.0 and 12.2.1.4.0. This is an easily exploitable vulnerability that allows unauthenticated attackers with network access via HTTP to compromise Oracle Access Manager.": "Podatność w komponencie OpenSSO Agent narzędzia Oracle Fusion Middleware w wersjach 11.1.2.3.0, 12.2.1.3.0 i 12.2.1.4.0 umożliwia atakującemu zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Fifteen WordPress themes are susceptible to code injection using a version of epsilon-framework, due to lack of capability and CSRF nonce checks in AJAX actions.": "Wykryto szablon WordPress umożliwiający zdalne wykonanie kodu ze względu na podatność w narzędziu epsilon-framework."
    + RCE_EFFECT_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "[no description] PHP Debug bar": "Wykryto narzędzie PHP Debug Bar, które umożliwia pobranie wrażliwych informacji, np. konfiguracji aplikacji. Rekomendujemy, aby to narzędzie nie było dostępne publicznie.",
    "The DebugBar integrates easily into projects and can display profiling data from any part of your application.This template detects exposed PHP Debug Bars by looking for known response bodies and the `phpdebugbar-id` in headers.": "Wykryto narzędzie PHP Debug Bar, które umożliwia pobranie wrażliwych informacji, np. konfiguracji aplikacji. Rekomendujemy, aby to narzędzie nie było dostępne publicznie.",
    "The DebugBar integrates easily in any projects and can display profiling data from any part of your application. It comes built-in with data collectors for standard PHP features and popular projects.": "Wykryto narzędzie PHP Debug Bar, które umożliwia pobranie wrażliwych informacji, np. konfiguracji aplikacji. Rekomendujemy, aby to narzędzie nie było dostępne publicznie.",
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
    "group:env-file": "Wykryto plik .env zawierający konfigurację systemu. Ponieważ może on zawierać np. hasła, nie powinien być dostępny publicznie.",
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
    "Magento Cacheleak is an implementation vulnerability, result of bad implementation of web-server configuration for Magento platform. Magento was developed to work under the Apache web-server which natively works with .htaccess files, so all needed configuration directives specific for various internal Magento folders were placed in .htaccess files.  When Magento is installed on web servers that are ignoring .htaccess files (such as nginx), an attacker can get access to internal Magento folders (such as the Magento cache directory) and extract sensitive information from cache files.": "Wykryto podatność Magento Cacheleak: gdy narzędzie Magento jest zainstalowane na serwerze HTTP niewspierającym plików .htaccess, to zabezpieczenia zapewniane przez pliki .htaccess są wyłączone, co umożliwia atakującemu dostęp do wewnętrznych folderów Magento i np. pobranie wrażliwych danych z pamięci podręcznej. Rekomendujemy zmianę konfiguracji systemu tak, aby takie dane nie były dostępne publicznie.",
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
    "[no description] http/exposures/logs/microsoft-runtime-error.yaml": "Wykryto stronę błędu oprogramowania Microsoft, dzięki której atakujący może zdobyć informacje na temat systemu.",
    "Private SSL, SSH, TLS, and JWT keys were detected.": "Wykryto klucze prywatne SSL, SSH, TLS lub JWT."
    + DATA_HIDE_HINT,
    "WordPress Site Editor through 1.1.1 allows remote attackers to retrieve arbitrary files via the ajax_path parameter to editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php.": "Wtyczka WordPress o nazwie WordPress Site Editor w wersjach do 1.1.1 zezwala atakującym na pobieranie dowolnych plików z serwera."
    + WORDPRESS_UPDATE_HINT,
    "MCMS 5.2.5 contains a SQL injection vulnerability via the categoryId parameter in the file IContentDao.xml. An attacker can potentially obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.": "MCMS w wersji 5.2.5 zawiera podatność SQL Injection. Atakujący może pobrać wrażliwe informacje z bazy danych, zmodyfikować dane i wykonywać dowolne operacje administracyjne na podatnej stronie."
    + UPDATE_HINT,
    "Adminer before 4.7.9 is susceptible to server-side request forgery due to exposure of sensitive information in error messages. Users of Adminer versions bundling all drivers, e.g. adminer.php, are affected. An attacker can possibly obtain this information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.": "Narzędzie Adminer w wersji poniżej 4.7.9 zawiera podatność Server-Side Request Forgery. Może to umożliwić atakującemu komunikację z usługami w sieci wewnętrznej, a w niektórych konfiguracjach również uzyskanie nieuprawnionego dostępu do systemu."
    + UPDATE_HINT,
    "[no description] http/fuzzing/ssrf-via-proxy.yaml": "Wykryto podatność Server-Side Request Forgery. Może ona umożliwić atakującemu komunikację z usługami w sieci wewnętrznej, a w niektórych konfiguracjach również uzyskanie nieuprawnionego dostępu do systemu.",
    "WordPress Fusion Builder plugin before 3.6.2 is susceptible to server-side request forgery. The plugin does not validate a parameter in its forms, which can be used to initiate arbitrary HTTP requests. The data returned is then reflected back in the application's response. An attacker can potentially interact with hosts on the server's local network, bypass firewalls, and access control measures.": "Wtyczka WordPress o nazwie Fusion Builder w wersji poniżej 3.6.2 zawiera podatność Server-Side Request Forgery. Może to umożliwić atakującemu komunikację z usługami w sieci wewnętrznej, a w niektórych konfiguracjach również uzyskanie nieuprawnionego dostępu do systemu."
    + WORDPRESS_UPDATE_HINT,
    "WordPress Metform plugin through 2.1.3 is susceptible to information disclosure due to improper access control in the ~/core/forms/action.php file. An attacker can view all API keys and secrets of integrated third-party APIs such as that of PayPal, Stripe, Mailchimp, Hubspot, HelpScout, reCAPTCHA and many more.": "Wtyczka WordPress o nazwie Metform w wersjach do 2.1.3 umożliwia atakującemu pobranie kluczy API usług takich jak PayPal, Stripe, Mailchimp, Hubspot, HelpScout czy reCAPTCHA."
    + WORDPRESS_UPDATE_HINT,
    "[no description] vulnerabilities/generic/cache-poisoning-xss.yaml": "Wykryto podatność Cache Poisoning, umożliwiającą atakującemu zmianę treści prezentowanych innym użytkownikom serwisu, w tym umieszczenie tam szkodliwego oprogramowania."
    + BUG_FIX_HINT,
    "Cache Poisoning leads to Stored XSS.": "Wykryto podatność Cache Poisoning, umożliwiającą atakującemu zmianę treści prezentowanych innym użytkownikom serwisu, w tym umieszczenie tam szkodliwego oprogramowania."
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
    "Blackboard contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Narzędzie Blackboard zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Sickbeard contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Narzędzie Sickbeard zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "JavaMelody contains a cross-site scripting vulnerability via the monitoring parameter. An attacker can execute arbitrary script in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Narzędzie JavaMelody zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Discourse contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.": "Narzędzie Discourse zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Drone configuration was discovered.": "Wykryto konfigurację narzędzia Drone." + DATA_HIDE_HINT,
    "Seagate NAS OS version 4.3.15.1 has insufficient access control which allows attackers to obtain information about the NAS without authentication via empty POST requests in /api/external/7.0/system.System.get_infos.": "Seagate NAS OS w wersji 4.3.15.1 zawiera niewystarczające mechanizmy kontroli dostępu, co umożliwia atakującemu nieuprawnione uzyskanie informacji o systemie."
    + UPDATE_HINT,
    "Geoserver default admin credentials were discovered.": "Wykryto, że domyślne dane do logowania do narzędzia Geoserver umożliwiają logowanie."
    + DEFAULT_CREDENTIALS_HINT,
    "[no description] http/vulnerabilities/wordpress/wp-config-setup.yaml": "Wykryto plik instalacyjny /wp-admin/setup-config.php, umożliwiający instalację systemu WordPress. Udostępnienie takiego panelu umożliwi atakującemu wykonanie dowolnego kodu na serwerze. Rekomendujemy, aby takie zasoby nie były dostępne publicznie.",
    "Some Dahua products contain an authentication bypass during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.": "Wykryto produkt Dahua zawierający możiwość ominięcia uwierzytelniania.",
    "SAP xMII 15.0 for SAP NetWeaver 7.4 is susceptible to a local file inclusion vulnerability in the GetFileList function. This can allow remote attackers to read arbitrary files via a .. dot dot) in the path parameter to /Catalog, aka SAP Security Note 2230978.": "Narzędzie SAP xMII 15.0 dla SAP NetWeaver 7.4 zawiera podatność Local File Inclusion, umożliwiającą atakującym pobranie dowolnego pliku z serwera."
    + UPDATE_HINT,
    'Revive Adserver 4.2 is susceptible to remote code execution. An attacker can send a crafted payload to the XML-RPC invocation script and trigger the unserialize) call on the "what" parameter in the "openads.spc" RPC method. This can be exploited to perform various types of attacks, e.g. serialize-related PHP vulnerabilities or PHP object injection. It is possible, although unconfirmed, that the vulnerability has been used by some attackers in order to gain access to some Revive Adserver instances and deliver malware through them to third-party websites.': "Narzędzie Revive Adserver w wersji 4.2 zawiera podatność typu Remote Code Execution."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Revive Adserver before 5.1.0 contains an open redirect vulnerability via the dest, oadest, and ct0 parameters of the lg.php and ck.php delivery scripts. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.": "Revive Adserver w wersji poniżej 5.1.0 zawiera podatność Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie."
    + UPDATE_HINT,
    "WordPress WebP Converter for Media < 4.0.3 contains a file (passthru.php) which does not validate the src parameter before redirecting the user to it, leading to an open redirect issue.": "Wtyczka WordPress o nazwie WebP Converter for Media w wersji poniżej 4.0.3 zawiera podatność Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie."
    + WORDPRESS_UPDATE_HINT,
    "In Apache HTTP server 2.4.0 to 2.4.39, Redirects configured with mod_rewrite that were intended to be self-referential might be fooled by encoded newlines and redirect instead to an unexpected URL within the request URL.": "Serwer Apache w wersji 2.4.0 do 2.4.39 zawiera podatność Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie."
    + UPDATE_HINT,
    "IceWarp Mail Server contains an open redirect via the referer parameter. This can lead to phishing attacks or other unintended redirects.": "Wykryto serwer IceWarp zawierający podatność Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie."
    + UPDATE_HINT,
    "[no description] http/takeovers/tilda-takeover.yaml": "Wykryto domenę kierującą do narzędzia Tilda, ale domena docelowa jest wolna. Atakujący może zarejestrować domenę w narzędziu Tilda, aby serwować tam swoje treści. Jeśli domena nie jest używana, rekomendujemy jej usunięcie.",
    "tumblr takeover was detected.": "Wykryto domenę kierującą do serwisu Tumblr, ale strona docelowa nie istnieje. Atakujący może utworzyć stronę w serwisie Tumblr, aby serwować tam swoje treści. Jeśli domena nie jest używana, rekomendujemy jej usunięcie.",
    "AWS Bucket takeover was detected.": "Wykryto domenę kierującą do zasobu AWS S3, który nie istnieje. Atakujący może utworzyć taki zasób, aby serwować tam swoje treści. Jeśli domena nie jest używana, rekomendujemy jej usunięcie.",
    "[no description] http/misconfiguration/clockwork-dashboard-exposure.yaml": "Wykryto publicznie dostępny panel narzędzia Clockwork. Rekomendujemy, aby takie zasoby nie były dostępne publicznie.",
    "[no description] http/vulnerabilities/generic/cache-poisoning-xss.yaml": "Wykryto podatność Cache Poisoning, umożliwiającą atakującemu zmianę treści prezentowanych innym użytkownikom serwisu, w tym umieszczenie tam szkodliwego oprogramowania."
    + BUG_FIX_HINT,
    "The Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services) versions 0.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0 contain an easily exploitable vulnerability that allows unauthenticated attackers with network access via HTTP to compromise Oracle WebLogic Server.": "Komponent Oracle WebLogic Server narzędzia Oracle Fusion Middleware w wersji m.in. 0.3.6.0.0, 12.1.3.0.0 i 12.2.1.3.0 (ale też pojedynczych innych wersjach) zawiera podatność umożliwiającą zdalne wykonanie kodu."
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
    "Roundcube Log file was disclosed.": "Wykryto dziennik zdarzeń systemu Roundcube. Może on zawierać takie dane jak np. informacje o nadawcach i odbiorcach e-maili czy informacje o konfiguracji systemu."
    + DATA_HIDE_HINT,
    "[no description] http/exposures/logs/roundcube-log-disclosure.yaml": "Wykryto dziennik zdarzeń systemu Roundcube. Może on zawierać takie dane jak np. informacje o nadawcach i odbiorcach e-maili czy informacje o konfiguracji systemu."
    + DATA_HIDE_HINT,
    "[no description] http/takeovers/netlify-takeover.yaml": "Domena jest skonfigurowana, aby serwować treści z narzędzia Netlify, ale domena docelowa jest wolna. Atakujący może potencjalnie zarejestrować taką domenę w serwisie Netlify aby umieścić tam swoje treści. Jeśli domena jest nieużywana, rekomendujemy jej usunięcie.",
    "WordPress Zoomsounds plugin 6.45 and earlier allows arbitrary files, including sensitive configuration files such as wp-config.php, to be downloaded via the `dzsap_download` action using directory traversal in the `link` parameter.": "Wtyczka WordPress o nazwie Zoomsounds w wersji 6.45 i wcześniejszych umożliwia atakującemu pobieranie dowolnych plików z serwera, w tym plików konfiguracyjnych."
    + UPDATE_HINT,
    "TurboCRM contains a cross-site scripting vulnerability which allows a remote attacker to inject arbitrary JavaScript into the response returned by the application.": "Narzędzie TurboCRM zawiera podatność Cross-Site Scripting, umożliwiającą wstrzykiwanie dowolnego kodu JavaScript do odpowiedzi aplikacji."
    + UPDATE_HINT,
    "[no description] http/misconfiguration/elasticsearch.yaml": "Wykryto, że dane w systemie Elasticsearch są publicznie dostępne. Rekomendujemy zmianę tej konfiguracji.",
    "The HTTP PUT method is normally used to upload data that is saved on the server at a user-supplied URL. If enabled, an attacker may be able to place arbitrary, and potentially malicious, content into the application. Depending on the server's configuration, this may lead to compromise of other users (by uploading client-executable scripts), compromise of the server (by uploading server-executable code), or other attacks.": "Wykryto, że metoda HTTP PUT jest włączona, co umożliwia atakującemu umieszczanie dowolnych plików na serwerze, co może doprowadzić m.in. do zdalnego wykonania kodu."
    + RCE_EFFECT_DESCRIPTION,
    "Microsoft Exchange Server is vulnerable to a remote code execution vulnerability. This CVE ID is unique from CVE-2021-31196, CVE-2021-31206.": "Wykryto, że obecnie używana wersja Microsoft Exchange Server zawiera podatność CVE-2021-34473 umożliwiającą zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "GitLab CE/EE 14.0 prior to 14.10.5, 15.0 prior to 15.0.4, and 15.1 prior to 15.1.1 is susceptible to remote code execution. An authenticated user authorized to import projects can import a maliciously crafted project, thus possibly being able to execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.": "GitLab CE/EE 14.0 w wersji poniżej 14.10.5, 15.0 w wersji poniżej 15.0.4 i 15.1 w wersji poniżej 15.1.1 umożliwia zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "GitLab CE/EE contains a hard-coded credentials vulnerability. A hardcoded password was set for accounts registered using an OmniAuth provider (e.g. OAuth, LDAP, SAML), allowing attackers to potentially take over accounts. This template attempts to passively identify vulnerable versions of GitLab without the need for an exploit by matching unique hashes for the application-<hash>.css file in the header for unauthenticated requests. Positive matches do not guarantee exploitability. Affected versions are 14.7 prior to 14.7.7, 14.8 prior to 14.8.5, and 14.9 prior to 14.9.2.": "GitLab CE/EE w wersji 14.7 poniżej 14.7.7, 14.8 poniżej 14.8.5 i 14.9 poniżej 14.9.2 umożliwia atakującym przejęcie niektórych rodzajów kont."
    + UPDATE_HINT,
    "YesWiki before 2022-07-07 contains a SQL injection vulnerability via the id parameter in the AccueiL URL. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.": "Narzędzie YesWiki w wersji poniżej 2022-07-07 zawiera podatność SQL Injection umożliwiającą pobranie całej zawartości bazy danych."
    + UPDATE_HINT,
    "Discover history for bash, ksh, sh, and zsh": "Wykryto historię poleceń powłoki bash, ksh, sh lub zsh."
    + DATA_HIDE_HINT,
    "The host is configured as a proxy which allows access to other hosts on the internal network.": "Wykryto, że serwer jest skonfigurowany jako serwer proxy umożliwiający dostęp do hostów w sieci wewnętrznej.",
    "The Openstack host is configured as a proxy which allows access to the instance metadata service. This could allow significant access to the host/infrastructure.": "Wykryto, że serwer HTTP jest skonfigurowany jako serwer proxy umożliwiający dostęp do wewnętrznych metadanych OpenStack, w tym potencjalnie do haseł dostępowych. Rekomendujemy, aby serwer proxy nie miał dostępu do takich zasobów.",
    "The AWS host is configured as a proxy which allows access to the metadata service. This could allow significant access to the host/infrastructure.": "Wykryto, że serwer HTTP jest skonfigurowany jako serwer proxy umożliwiający dostęp do wewnętrznych metadanych AWS, w tym potencjalnie do haseł dostępowych. Rekomendujemy, aby serwer proxy nie miał dostępu do takich zasobów.",
    "The host is configured as a proxy which allows access to the metadata provided by a cloud provider such as AWS or OVH. This could allow significant access to the host/infrastructure.": "Wykryto, że serwer HTTP jest skonfigurowany jako serwer proxy umożliwiający dostęp do wewnętrznych metadanych dostawcy takiego AWS czy OVH, w tym potencjalnie do haseł dostępowych. Rekomendujemy, aby serwer proxy nie miał dostępu do takich zasobów.",
    "[no description] http/exposures/files/ds-store-file.yaml": "Wykryto plik .DS_Store, zawierający informację o nazwach plików w katalogu, w tym potencjalnie np. kopii zapasowych lub innych plików, które nie powinny być publicznie dostępne. Rekomendujemy, aby takie dane nie były dostępne publicznie.",
    "A .DS_Store file was found. This file may contain names of files that exist on the server, including backups or other files that aren't meant to be publicly available.": "Wykryto plik .DS_Store, zawierający informację o nazwach plików w katalogu, w tym potencjalnie np. kopii zapasowych lub innych plików, które nie powinny być publicznie dostępne. Rekomendujemy, aby takie pliki nie były dostępne publicznie.",
    "[no description] http/misconfiguration/server-status-localhost.yaml": "Wykryto, że końcówka /server-status serwera Apache jest publicznie dostępna, udostępniając takie informacje jak np. konfigurację serwera, adresy IP użytkowników czy odwiedzane przez nich strony. Rekomendujemy, aby takie zasoby nie były dostępne publicznie.",
    "Apache Server Status page is exposed, which may contain information about pages visited by the users, their IPs or sensitive information such as session tokens.": "Wykryto, że końcówka /server-status serwera Apache jest publicznie dostępna, udostępniając takie informacje jak np. konfigurację serwera, adresy IP użytkowników czy odwiedzane przez nich strony. Rekomendujemy, aby takie zasoby nie były dostępne publicznie.",
    "Server Status is exposed.": "Wykryto, że końcówka /server-status serwera Apache jest publicznie dostępna, udostępniając takie informacje jak np. konfigurację serwera, adresy IP użytkowników czy odwiedzane przez nich strony. Rekomendujemy, aby takie zasoby nie były dostępne publicznie.",
    "Symfony database configuration file was detected and may contain database credentials.": "wykryto plik konfiguracyjny bazy danych dla frameworku Symfony - taki plik może zawierać np. hasła dostępowe."
    + DATA_HIDE_HINT,
    "Apache Tomcat JK (mod_jk) Connector 1.2.0 to 1.2.44 allows specially constructed requests to expose application functionality through the reverse proxy. It is also possible in some configurations for a specially constructed request to bypass the access controls configured in httpd. While there is some overlap between this issue and CVE-2018-1323, they are not identical.": "Narzędzie Apache Tomcat JK (mod_jk) Connector w wersjach od 1.2.0 do 1.2.44 umożliwia atakującemu nieuprawniony dostęp do części funkcjonalności aplikacji."
    + UPDATE_HINT,
    "GeoServer through 2.18.5 and 2.19.x through 2.19.2 allows server-side request forgery via the option for setting a proxy host.": "Narzędzie GeoServer w wersji do 2.18.5 i w wersjach 2.19.x do 2.19.2 zawiera podatność typu Server-Side Request Forgery umożliwiającą atakującemu komunikację z systemami w sieci lokalnej."
    + UPDATE_HINT,
    "The WordPress Social Login and Register (Discord, Google, Twitter, LinkedIn) plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 7.6.4. This is due to insufficient encryption on the user being supplied during a login validated through the plugin. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, if they know the email address associated with that user. This was partially patched in version 7.6.4 and fully patched in version 7.6.5.": "Wtyczka WordPress o nazwie Social Login and Register w wersji do 7.6.5 włącznie umożliwia atakującemu ominięcie uwierzytelnienia i nieuprawniony dostęp administracyjny do systemu."
    + WORDPRESS_UPDATE_HINT,
    "ProcessMaker 3.5.4 and prior is vulnerable to local file inclusion.": "Narzędzie ProcessMaker w wersji 3.5.4 i wcześniejszych umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "The CMNC-200 IP Camera has a built-in web server that is vulnerable to directory transversal attacks, allowing access to any file on the camera file system.": "Wykryto, że kamera CMNC-200 zawiera podatność Directory Traversal umożliwiającą odczyt dowolnych plików z dysku."
    + UPDATE_HINT,
    "FTP credentials were detected.": "Wykryto plik ftpsync.settings zawierający dane logowania serwera FTP. Rekomendujemy, aby takie pliki nie były dostępne publicznie.",
    "Genie Access WIP3BVAF WISH IP 3MP IR Auto Focus Bullet Camera devices through 3.X are vulnerable to local file inclusion via the web interface, as demonstrated by reading /etc/shadow.": "Wykryto, że urządzenie Genie Access WIP3BVAF WISH IP 3MP IR Auto Focus Bullet Camera zawiera podatność Directory Traversal umożliwiającą odczyt dowolnych plików z dysku.",
    "Apache Rocketmq Unauthenticated Access were detected.": "Wykryto, że dostęp do narzędzia Apache Rocketmq nie wymaga logowania. Rekomendujemy włączenie uwierzytelniania.",
    "Tensorflow Tensorboard was able to be accessed with no authentication requirements in place.": "Wykryto, że dostęp do narzędzia Tensorflow Tensorboard nie wymaga logowania. Rekomendujemy włączenie uwierzytelniania.",
    "Nginx server is vulnerable to local file inclusion.": "Wykryto, że serwer NGINX jest niepoprawnie skonfigurowany, co umożliwia odczyt dowolnych plików z serwera. Rekomendujemy zmianę tej konfiguracji.",
    "Bullwark Momentum Series JAWS 1.0 is vulnerable to local file inclusion.": "Wykryto, że Bullwark Momentum Series JAWS 1.0 zawiera podatność Directory Traversal umożliwiającą odczyt dowolnych plików z dysku."
    + UPDATE_HINT,
    "IBM InfoPrint 4247-Z03 Impact Matrix Printer is subject to local file inclusion.": "Wykryto, że drukarka IBM InfoPrint 4247-Z03 Impact Matrix Printer zawiera podatność Directory Traversal umożliwiającą odczyt dowolnych plików z dysku."
    + UPDATE_HINT,
    "Generic Linux is subject to local file Inclusion on searches for /etc/passwd on passed URLs.": "Wykryto serwer HTTP systemu Linux skonfigurowany w sposób umożliwiający atakującemu odczyt dowolnych plików z dysku."
    + UPDATE_HINT,
    "Generic Linux is subject to Local File Inclusion - the vulnerability was identified by requesting /etc/passwd from the server.": "Wykryto serwer HTTP systemu Linux skonfigurowany w sposób umożliwiający atakującemu odczyt dowolnych plików z dysku."
    + UPDATE_HINT,
    'Zyxel VMG1312-B10D 5.13AAXA.8 is susceptible to local file inclusion. A remote unauthenticated attacker can send a specially crafted URL request containing "dot dot" sequences (/../), conduct directory traversal attacks, and view arbitrary files.': "Wykryto urządzenie Zyxel VMG1312-B10D 5.13AAXA.8 zawierające podatność Directory Traversal umożliwiającą odczyt dowolnych plików z dysku."
    + UPDATE_HINT,
    "Hanming Video Conferencing is vulnerable to local file inclusion.": "Wykryto, że narzędzie Hanming Video Conferencing zawiera podatność Local File Inclusion.",
    "Barcode is a GLPI plugin for printing barcodes and QR codes. GLPI instances version 2.x prior to version 2.6.1 with the barcode plugin installed are vulnerable to a path traversal vulnerability.": "Wykryto, że wtyczka GLPI w wersji 2.x poniżej 2.6.1 o nazwie Barcode umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "GoCD contains a critical information disclosure vulnerability whose exploitation allows unauthenticated attackers to leak configuration information including build secrets and encryption keys.": "Narzędzie GoCD zawiera podatność umożliwiającą atakującemu pobranie danych takich jak np. klucze szyfrujące.",
    'WordPress Church Admin 0.33.2.1 is vulnerable to local file inclusion via the "key" parameter of plugins/church-admin/display/download.php.': "Wtyczka WordPress o nazwie Church Admin w wersji 0.33.2.1 umożliwia atakującemu odczyt dowolnych plików z serwera."
    + WORDPRESS_UPDATE_HINT,
    "WordPress Localize My Post 1.0 is susceptible to local file inclusion via the ajax/include.php file parameter.": "Wtyczka WordPress o nazwie Localize My Post w wersji 1.0 umożliwia atakującemu odczyt dowolnych plików z serwera i potencjalnie zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "NCBI ToolBox 2.0.7 through 2.2.26 legacy versions contain a path traversal vulnerability via viewcgi.cgi which may result in reading of arbitrary files (i.e., significant information disclosure) or file deletion via the nph-viewgif.cgi query string.": "Narzędzie NCBI ToolBox w wersji od 2.0.7 do 2.2.26 zawiera podatność, która umożliwia atakującemu odczyt lub usunięcie dowolnych plików z serwera."
    + UPDATE_HINT,
    "SysAid Help Desk before 15.2 contains multiple local file inclusion vulnerabilities which can allow remote attackers to read arbitrary files via .. (dot dot) in the fileName parameter of getGfiUpgradeFile or cause a denial of service (CPU and memory consumption) via .. (dot dot) in the fileName parameter of calculateRdsFileChecksum.": "Narzędzie SysAid Help Desk w wersji poniżej 15.2 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera lub atak typu DoS."
    + UPDATE_HINT,
    "A local file inclusion vulnerability exists in version BIQS IT Biqs-drive v1.83 and below when sending a specific payload as the file parameter to download/index.php. This allows the attacker to read arbitrary files from the server with the permissions of the configured web-user.": "Narzędzie BIQS IT Biqs-drive w wersji v1.83 i niższych zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "WordPress Candidate Application Form <= 1.3 is susceptible to arbitrary file downloads because the code in downloadpdffile.php does not do any sanity checks.": "Wtyczka WordPress o nazwie Candidate Application Form w wersji 1.3 i niższych zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + WORDPRESS_UPDATE_HINT,
    "Loytec LGATE-902 versions prior to 6.4.2 suffers from a local file inclusion vulnerability.": "Wykryto, że Loytec LGATE-902 w wersjach poniżej 6.4.2 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "LOYTEC LGATE-902 6.3.2 is susceptible to local file inclusion which could allow an attacker to manipulate path references and access files and directories (including critical system files) that are stored outside the root folder of the web application running on the device. This can be used to read and configuration files containing, e.g., usernames and passwords.": "Wykryto, że Loytec LGATE-902 w wersji 6.3.2 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "Piano LED Visualizer 1.3 and prior are vulnerable to local file inclusion.": "Piano LED Visualizer w wersji 1.3 i wcześniejszych zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "In avatar_uploader v7.x-1.0-beta8 the view.php program doesn't restrict file paths, allowing unauthenticated users to retrieve arbitrary files.": "Narzędzie avatar_uploader w wersji v7.x-1.0-beta8 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "cGit < 1.2.1 via cgit_clone_objects has a directory traversal vulnerability when `enable-http-clone=1` is not turned off, as demonstrated by a cgit/cgit.cgi/git/objects/?path=../ request.": "narzędzie cGit w wersji poniżej 1.2.1 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "Patreon WordPress before version 1.7.0 is vulnerable to unauthenticated local file inclusion that could be abused by anyone visiting the site. Exploitation by an attacker could leak important internal files like wp-config.php, which contains database credentials and cryptographic keys used in the generation of nonces and cookies.": "Wtyczka WordPress o nazwie Patreon w wersji poniżej 1.7.0 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + WORDPRESS_UPDATE_HINT,
    "SAP xMII 15.0 for SAP NetWeaver 7.4 is susceptible to a local file inclusion vulnerability in the GetFileList function. This can allow remote attackers to read arbitrary files via a .. (dot dot) in the path parameter to /Catalog, aka SAP Security Note 2230978.": "SAP xMII 15.0 dla SAP NetWeaver zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "A Local File inclusion vulnerability in test.php in spreadsheet-reader 0.5.11 allows remote attackers to include arbitrary files via the File parameter.": "Narzędzie spreadsheet-reader w wersji 0.5.11 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "WordPress Wordfence 7.4.5 is vulnerable to local file inclusion.": "Wtyczka WordPress o nazwie Wordfence w wersji 7.4.5 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + WORDPRESS_UPDATE_HINT,
    "MagicFlow is susceptible to local file inclusion vulnerabilities because it allows remote unauthenticated users to access locally stored files on the server and return their content via the '/msa/main.xp' endpoint and the 'Fun' parameter.": "Narzędzie MagicFlow zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera.",
    "Longjing Technology BEMS API 1.21 is vulnerable to local file inclusion. Input passed through the fileName parameter through the downloads API endpoint is not properly verified before being used to download files. This can be exploited to disclose the contents of arbitrary and sensitive files through directory traversal attacks.": "Narzędzie Longjing Technology BEMS API 1.21 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "Surreal ToDo 0.6.1.2 is vulnerable to local file inclusion via index.php and the content parameter.": "Narzędzie Surreal ToDo w wersji 0.6.1.2 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "Linear eMerge E3-Series devices are vulnerable to local file inclusion.": "Urządzenia Linear eMerge E3-Series zawierają podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "ZOHO WebNMS Framework before version 5.2 SP1 is vulnerable local file inclusion which allows an attacker to read arbitrary files via a .. (dot dot) in the fileName parameter to servlets/FetchFile.": "ZOHO WebNMS Framework w wersji poniżej 5.2 SP1 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "WordPress GraceMedia Media Player plugin 1.0 is susceptible to local file inclusion via the cfg parameter.": "Wtyczka WordPress o nazwie GraceMedia Media Player w wersji 1.0 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + WORDPRESS_UPDATE_HINT,
    "WordPress Wechat Broadcast plugin 1.2.0 and earlier allows Directory Traversal via the Image.php url parameter.": "Wtyczka WordPress o nazwie Wechat Broadcast plugin w wersji 1.2.0 i wcześniejszych zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + WORDPRESS_UPDATE_HINT,
    "Jeecg P3 Biz Chat 1.0.5 allows remote attackers to read arbitrary files through specific parameters.": "Jeecg P3 Biz Chat 1.0.5 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "Webbdesign SL-Studio is vulnerable to local file inclusion.": "Webbdesign SL-Studio zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "Oracle Fatwire 6.3 suffers from a path traversal vulnerability in the getSurvey.jsp endpoint.": "Oracle Fatwire w wersji 6.3 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "Groupoffice 3.4.21 is vulnerable to local file inclusion.": "Groupoffice 3.4.21 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "OrbiTeam BSCW Server versions 5.0.x, 5.1.x, 5.2.4 and below, 7.3.x and below, and 7.4.3 and below are vulnerable to unauthenticated local file inclusion.": "OrbiTeam BSCW Server w wersji 5.0.x, 5.1.x, 5.2.4 i wcześniejszych, 7.3.x i wcześniejszych i 7.4.3 i wcześniejszych zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "Asanhamayesh CMS 3.4.6 is vulnerable to local file inclusion.": "Asanhamayesh CMS w wersji 3.4.6 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "Portal do Software Publico Brasileiro i3geo 7.0.5 is vulnerable to local file inclusion in the component codemirror.php, which allows attackers to execute arbitrary PHP code via a crafted HTTP request.": "Portal do Software Publico Brasileiro i3geo 7.0.5 zawiera podatność umożliwiającą zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Karel IP Phone IP1211 Web Management Panel is vulnerable to local file inclusion and can allow remote attackers to access arbitrary files stored on the remote device via the 'cgiServer.exx' endpoint and the 'page' parameter.": "Karel IP Phone IP1211 Web Management Panel zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "Joomla! Roland Breedveld Album 1.14 (com_album) is susceptible to local file inclusion because it allows remote attackers to access arbitrary directories and have unspecified other impact via a .. (dot dot) in the target parameter to index.php.": "Wtyczka Joomla! o nazwie Roland Breedveld Album w wersji 1.14 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "PilusCart versions 1.4.1 and prior suffer from a file disclosure vulnerability via local file inclusion.": "PilusCart w wersji 1.4.1 i wcześniejszych zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "A PHP remote file inclusion vulnerability in core/include/myMailer.class.php in the Visites (com_joomla-visites) component 1.1 RC2 for Joomla! allows remote attackers to execute arbitrary PHP code via a URL in the mosConfig_absolute_path parameter.": "Komponent Joomla! o nazwie Visites (com_joomla-visites) w wersji 1.1 RC2 zawiera podatność umożliwiającą zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "The ECOA BAS controller suffers from a directory traversal content disclosure vulnerability. Using the GET parameter cpath in File Manager (fmangersub), attackers can disclose directory content on the affected device": "Kontroler ECOA BAS zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera.",
    "PhpMyAdmin before version 4.8.2 is susceptible to local file inclusion that allows an attacker to include (view and potentially execute) files on the server. The vulnerability comes from a portion of code where pages are redirected and loaded within phpMyAdmin, and an improper test for whitelisted pages. An attacker must be authenticated, except in the \"$cfg['AllowArbitraryServer'] = true\" case (where an attacker can specify any host he/she is already in control of, and execute arbitrary code on phpMyAdmin) and the \"$cfg['ServerDefault'] = 0\" case (which bypasses the login requirement and runs the vulnerable code without any authentication).": "PhpMyAdmin w wersji poniżej 4.8.2 zawiera podatność umożliwiającą atakującemu odczyt dowolnych plików z serwera i potencjalnie zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Carel pCOWeb HVAC BACnet Gateway 2.1.0 is vulnerable to local file inclusion because of input passed through the 'file' GET parameter through the 'logdownload.cgi' Bash script is not properly verified before being used to download log files. This can be exploited to disclose the contents of arbitrary and sensitive files via directory traversal attacks.": "Carel pCOWeb HVAC BACnet Gateway 2.1.0 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "EyeLock nano NXT suffers from a file retrieval vulnerability when input passed through the 'path' parameter to 'logdownload.php' script is not properly verified before being used to read files. This can be exploited to disclose contents of files from local resources.": "EyeLock nano NXT zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera.",
    "Eaton Intelligent Power Manager v1.6 allows an attacker to include a file via directory traversal, which can lead to sensitive information disclosure, denial of service and code execution.": "Eaton Intelligent Power Manager w wersji 1.6 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera i potencjalnie zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Tarantella Enterprise versions prior to 3.11 are susceptible to local file inclusion.": "Tarantella Enterprise w wersjach ponizęj 3.11 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "Multiple directory traversal vulnerabilities in Pandora FMS before 3.1.1 allow remote attackers to include and execute arbitrary local files via (1) the page parameter to ajax.php or (2) the id parameter to general/pandora_help.php, and allow remote attackers to include and execute, create, modify, or delete arbitrary local files via (3) the layout parameter to operation/agentes/networkmap.php.": "Pandora FMS w wersji poniżej 3.1.1 zawiera podatności, które umożliwiają atakującemu odczyt, edycję i usuwanie dowolnych plików z serwera i zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "LimeSurvey before 4.1.12+200324 is vulnerable to local file inclusion because it contains a path traversal vulnerability in application/controllers/admin/LimeSurveyFileManager.php.": "LimeSurvey w wersji poniżej 4.1.12+200324 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "The Ruoyi Management System contains a local file inclusion vulnerability that allows attackers to retrieve arbitrary files from the operating system.": "Ruoyi Management System zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera.",
    "openSIS 5.1 is vulnerable to local file inclusion and allows attackers to obtain potentially sensitive information by executing arbitrary local scripts in the context of the web server process. This may allow the attacker to compromise the application and computer; other attacks are also possible.": "openSIS w wersji 5.1 zawiera podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera i potencjalnie zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "A directory traversal vulnerability in Cisco Unified Communications Manager (CUCM) 5.x and 6.x before 6.1(5)SU2, 7.x before 7.1(5b)SU2, and 8.x before 8.0(3), and Cisco Unified Contact Center Express (aka Unified CCX or UCCX) and Cisco Unified IP Interactive Voice Response (Unified IP-IVR) before 6.0(1)SR1ES8, 7.0(x) before 7.0(2)ES1, 8.0(x) through 8.0(2)SU3, and 8.5(x) before 8.5(1)SU2, allows remote attackers to read arbitrary files via a crafted URL, aka Bug IDs CSCth09343 and CSCts44049.": "Cisco Unified Communications Manager (CUCM) w wersji 5.x, 6.x poniżej 6.1(5)SU2, 7.x poniżej 7.1(5b)SU2 i 8.x poniżej 8.0(3), Cisco Unified Contact Center Express i Cisco Unified IP Interactive Voice Response (Unified IP-IVR) w wersji poniżej 6.0(1)SR1ES8, 7.0(x) poniżej 7.0(2)ES1, 8.0(x) do 8.0(2)SU3 włącznie i 8.5(x) poniżej 8.5(1)SU2 zawierają podatność, która umożliwia atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "Redmine configuration file was detected.": "Wykryto plik konfiguracyjny systemu Redmine." + DATA_HIDE_HINT,
    # There are multiple plugins with this message, therefore we match by template path
    "http/vulnerabilities/wordpress/contus-video-gallery-sqli.yaml": "Wykryto, że wtyczka WordPress o nazwie Contus Video Gallery zawiera podatność SQL Injection, umożliwiającą atakującemu pobranie całej zawartości bazy danych."
    + WORDPRESS_UPDATE_HINT,
    "Nginx Virtual Host Traffic Status Module contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.": "Moduł Nginx Virtual Host Traffic Status zawiera podatność Reflected Cross-Site Scripting. Atakujący może spreparować link, który - gdy kliknięty przez administratora - wykona dowolną operację na stronie którą może wykonać administrator.",
    "[no description] http/takeovers/shopify-takeover.yaml": "Wykryto, że domena odsyła do serwisu Shopify, ale domena docelowa jest wolna. Atakujący może zarejestrować taką domenę w serwisie Shopify, aby umieścić tam swoje treści. Jeśli domena nie jest używana, rekomendujemy jej usunięcie.",
    "WordPress BuddyPress before version 7.2.1 is susceptible to a privilege escalation vulnerability that can be leveraged to perform remote code execution.": "Wtyczka WordPress o nazwie BuddyPress w wersji poniżej 7.2.1 umożliwia atakującemu zwiększenie swoich uprawnień a w konsekwencji zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "The Booked plugin for WordPress is vulnerable to authorization bypass due to missing capability checks on several functions hooked via AJAX actions in versions up to, and including, 2.2.5. This makes it possible for authenticated attackers with subscriber-level permissions and above to execute several unauthorized actions.": "Wtyczka WordPress o nazwie Booked w wersji do 2.2.5 umożliwia zalogowanemu atakującemu wykonywanie niektórych działań wymagających wyższych uprawnień."
    + WORDPRESS_UPDATE_HINT,
    "The threaddump endpoint provides a thread dump from the application's JVM.": "Wykryto zasób threaddump, umożliwiający pobranie informacji o wątkach aplikacji."
    + DATA_HIDE_HINT,
    "Sensitive environment variables may not be masked": "Możliwy jest odczyt konfiguracji środowiska, w której najprawdopodobniej znajdują się wrażliwe informacje dotyczące aplikacji."
    + DATA_HIDE_HINT,
    "WordPress Pricing Deals for WooCommerce plugin through 2.0.2.02 contains a SQL injection vulnerability. The plugin does not properly sanitise and escape a parameter before using it in a SQL statement via an AJAX action. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.": "Wtyczka WordPress o nazwie Pricing Deals for Woocommerce w wersji do 2.0.2.02 włącznie zawiera podatność SQL Injection umożliwiającą atakującemu pobranie całej zawartości bazy danych."
    + WORDPRESS_UPDATE_HINT,
    "The Photo Gallery by 10Web WordPress plugin before 1.6.0 does not validate and escape the bwg_tag_id_bwg_thumbnails_0 parameter before using it in a SQL statement via the bwg_frontend_data AJAX action (available to unauthenticated and authenticated users), leading to an unauthenticated SQL injection": "Wtyczka WordPress o nazwie Photo Gallery by 10Web w wersji poniżej 1.6.0 zawiera podatność SQL Injection, umożliwiającą atakującemu pobranie całej zawartości bazy danych."
    + WORDPRESS_UPDATE_HINT,
    "Wordpress installation files have been detected": "Wykryto instalator systemu WordPress. Rekomendujemy, aby takie zasoby nie były dostępne publicznie, ponieważ mogą umożliwić uzyskanie dostępu administracyjnego do systemu.",
    "FAUST iServer before 9.0.019.019.7 is susceptible to local file inclusion because for each URL request it accesses the corresponding .fau file on the operating system without preventing %2e%2e%5c directory traversal.": "FAUST iServer w wersji poniżej 9.0.019.019.7 zawiera podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    "TVT NVMS-1000 devices allow GET /.. local file inclusion attacks.": "Wykryto urządzenie TVT NVMS-1000 zawierające podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików z serwera.",
    "AxxonSoft Axxon Next suffers from a local file inclusion vulnerability.": "Wykryto, że AxxonSoft Axxon Next zawiera podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików z serwera.",
    "Oracle WebLogic Server (Oracle Fusion Middleware (component: WLS Core Components) is susceptible to a remote code execution vulnerability. Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 2.2.1.3.0 and 12.2.1.4.0. This easily exploitable vulnerability could allow unauthenticated attackers with network access via IIOP to compromise Oracle WebLogic Server.": "Wykryto, że komponent WLS Core Components oprogramowania Oracle WebLogic Server w wersjach 10.3.6.0.0, 12.1.3.0.0, 2.2.1.3.0 i 12.2.1.4.0 umożliwia zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "http/misconfiguration/springboot/springboot-logfile.yaml": "Wykryto dziennik zdarzeń frameworku Spring Boot."
    + DATA_HIDE_HINT,
    "http/vulnerabilities/other/sitemap-sql-injection.yaml": "Wykryto podatność SQL Injection w końcówce sitemap.xml, umożliwiającą atakującemu pobranie całej zawartości bazy danych. Rekomendujemy usunięcie podatności oraz weryfikację, czy nie występuje w innych miejscach systemu.",
    "WordPress Knews Multilingual Newsletters 1.1.0 plugin contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Wtyczka WordPress o nazwie Knews Multilingual Newsletters 1.1.0 zawiera podatność Cross-Site Scripting, umożliwiającą atakującemu spreparowanie linku, który - gdy kliknięty przez administratora - wykona dowolną akcję z jego uprawnieniami."
    + WORDPRESS_UPDATE_HINT,
    "Directory Traversal vulnerability in FileMage Gateway Windows Deployments v.1.10.8 and before allows a remote attacker to obtain sensitive information via a crafted request to the /mgmt/ component.": "FileMage Gateway w wersji v.1.10.8 i wcześniejszych zawiera podatność Directory Traversal umożliwiającą atakującemu pobieranie dowolnych plików z serwera."
    + UPDATE_HINT,
    "http/misconfiguration/installer/prestashop-installer.yaml": "Wykryto instalator systemu PrestaShop. Rekomendujemy, aby takie zasoby nie były dostępne publicznie, ponieważ mogą umożliwić atakującemu uzyskanie nieuprawnionego dostępu do systemu czy zmiany w jego konfiguracji.",
    "http/takeovers/vercel-takeover.yaml": "Wykryto domenę skonfigurowaną, aby serwować treści z serwisu Vercel, ale konto docelowe nie istnieje. Jeśli domena nie jest używana, rekomendujemy jej usunięcie, aby atakujący nie mógł zarejestrować domeny w serwisie Vercel i serwować swoich treści.",
    "Microweber before 1.1.20 is susceptible to information disclosure via userfiles/modules/users/controller/controller.php. An attacker can disclose the users database via a /modules/ POST request and thus potentially access sensitive information, modify data, and/or execute unauthorized operations.": "Narzędzie Microweber w wersji poniżej 1.1.20 umożliwia atakującemu pobranie danych użytkowników, a w konsekwencji dostęp do informacji wrażliwych i potencjalnie zmianę danych i wykonanie nieuprawnionych operacji."
    + UPDATE_HINT,
    "Amcrest IPM-721S V2.420.AC00.16.R.20160909 devices allow an unauthenticated attacker to download the administrative credentials.": "Urządzenia Amcrest IPM-721S V2.420.AC00.16.R.20160909 umożliwiają nieuwierzytelnionemu atakującemu pobranie danych dostępowych umożliwiających logowanie na konto administratora."
    + UPDATE_HINT,
    "Mida eFramework contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Wykryto podatność Cross-Site Scripting w narzędziu Mida eFramework. Ta podatność umożliwia atakującemu spreparowanie linku, który, gdy zostanie kliknięty przez administratora, umożliwi wykonanie dowolnej akcji z jego uprawnieniami.",
    "Vanguard Marketplace CMS 2.1 contains a cross-site scripting vulnerability in the message and product title tags and in the product search box.": "Narzędzie Vanguard Marketplace CMS w wersji 2.1 zawiera podatność Cross-Site Scripting, umożliwiającą atakującemu spreparowanie linku, który - gdy kliknięty przez administratora - wykona dowolną akcję z jego uprawnieniami."
    + UPDATE_HINT,
    "The default server implementation of TIBCO Software Inc.'s TIBCO JasperReports Library, TIBCO JasperReports Library Community Edition, TIBCO JasperReports Library for ActiveMatrix BPM, TIBCO JasperReports Server, TIBCO JasperReports Server Community Edition, TIBCO JasperReports Server for ActiveMatrix BPM, TIBCO Jaspersoft for AWS with Multi-Tenancy, and TIBCO Jaspersoft Reporting and Analytics for AWS contains a directory-traversal vulnerability that may theoretically allow web server users to access contents of the host system.": "Domyślna konfiguracja narzędzi TIBCO JasperReports Library, TIBCO JasperReports Library Community Edition, TIBCO JasperReports Library for ActiveMatrix BPM, TIBCO JasperReports Server, TIBCO JasperReports Server Community Edition, TIBCO JasperReports Server for ActiveMatrix BPM, TIBCO Jaspersoft for AWS with Multi-Tenancy i TIBCO Jaspersoft Reporting and Analytics for AWS zawiera podatność typu Directory Traversal, umożliwiającą atakującemu odczyt dowolnych plików z serwera. Rekomendujemy, aby narzędzie w takiej konfiguracji nie było publicznie dostępne.",
    "Detects potential time-based SQL injection.": "Wykryto podatność Time-Based SQL Injection, umożliwiającą pobranie dowolnej informacji z bazy danych. Rekomendujemy jej usunięcie i weryfikację, czy podobna podatność nie występuje również w innych miejscach systemu.",
    'If the owner of the app have set the security rules as true for both "read" & "write" an attacker can probably dump database and write his own data to firebase database.': "Wykryto bazę danych Firebase skonfigurowaną w taki sposób, że atakujący może zarówno odczytywać, jak i zapisywać do niej dane. Rekomendujemy zmianę tej konfiguracji.",
    "[no description] http/misconfiguration/installer/joomla-installer.yaml": "Wykryto instalator frameworku Joomla. Rekomendujemy, aby takie zasoby nie były dostępne publicznie, bo mogą umożliwić atakującemu uzyskanie nieuprawnionego dostępu do systemu.",
    "The Django settings.py file containing a secret key was discovered. An attacker may use the secret key to bypass many security mechanisms and potentially obtain other sensitive configuration information (such as database password) from the settings file.": "Wykryto plik settings.py zawierający konfigurację systemu Django. Atakujący może wykorzystać te dane aby ominąć mechanizmy bezpieczeństwa, lub (jeśli znajduje się tam np. hasło do bazy danych) uzyskać nieuprawniony dostęp do systemu."
    + DATA_HIDE_HINT,
    "SiteMinder contains a cross-site scripting vulnerability in the document object model. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Wykryto, że narzędzie SiteMinder zawiera podatność Cross-Site Scripting, umożliwiającą atakującemu spreparowanie linku, który, gdy zostanie kliknięty przez administratora, wykona dowolną akcję z jego uprawnieniami."
    + UPDATE_HINT,
    "service.pwd was discovered, which is likely to contain sensitive information.": "Wykryto plik service.pwd, który może zawierać wrażliwe informacje."
    + DATA_HIDE_HINT,
    "group:reflected-xss": "Wykryto podatność Reflected Cross-Site Scripting. Atakujący może spreparować link, który - gdy kliknięty przez administratora - wykona dowolną operację na stronie z jego uprawnieniami (np. modyfikację treści)."
    + BUG_FIX_HINT,
    "[no description] http/takeovers/github-takeover.yaml": "Wykryto domenę kierującą do serwisu Github Pages, ale domena docelowa jest wolna. Atakujący może zarejestrować taką domenę w serwisie Github Pages, aby serwować tam swoje treści. Jeśli domena nie jest używana, rekomendujemy jej usunięcie.",
    "[no description] http/takeovers/heroku-takeover.yaml": "Wykryto domenę kierującą do serwisu Heroku, ale domena docelowa jest wolna. Atakujący może zarejestrować taką domenę w serwisie Heroku, aby serwować tam swoje treści. Jeśli domena nie jest używana, rekomendujemy jej usunięcie.",
    "[no description] http/vulnerabilities/jenkins/unauthenticated-jenkins.yaml": "Wykryto publicznie dostępny system Jenkins, który nie wymaga zalogowania. Rekomendujemy, aby nie był on dostępny publicznie oraz zalecamy włączenie mechanizmu uwierzytelniania, ponieważ może umożliwić atakującemu uruchamianie własnych zadań lub nieuprawniony dostęp do informacji/kodu źródłowego.",
    "Possible Juicy Files can be discovered at this endpoint. Search / Grep for secrets like hashed passwords ( SHA ) , internal email disclosure etc.": "Wykryto konfigurację Adobe Experience Manager, mogącą zawierać dane, które nie powinny być dostępne publicznie.",
    "[no description] http/takeovers/webflow-takeover.yaml": "Wykryto domenę kierującą do narzędzia Webflow, ale domena docelowa jest wolna. Atakujący może zarejestrować domenę w narzędziu Webflow, aby serwować tam swoje treści. Jeśli domena nie jest używana, rekomendujemy jej usunięcie.",
    "HiBoss allows remote unauthenticated attackers to cause the server to execute arbitrary code via the 'server_ping.php' endpoint and the 'ip' parameter.": "Wykryto, że narzędzie HiBoss umożliwia niezalogowanym atakującym zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION,
    "phpwiki 1.5.4 is vulnerable to cross-site scripting and local file inclusion, and allows remote unauthenticated attackers to include and return the content of locally stored files via the 'index.php' endpoint.": "phpwiki w wersji 1.5.4 zawiera podatności Local File Inclusion i Cross-Site Scripting, umożliwiające atakującemu odczyt różnych plików z dysku i spreparowanie linku który - gdy kliknięty przez administratora - wykona dowolną operację na stronie którą może wykonać administrator (taką jak np. modyfikację treści). "
    + UPDATE_HINT,
    "Sites hosted by Global Domains International, Inc. have cross-site scripting and directory traversal vulnerabilities.": "Wykryto stronę hostowaną w Global Domains International, Inc. zawierającą podatności Directory Traversal i Cross-Site Scripting, umożliwiające atakującemu odczyt różnych plików z dysku i spreparowanie linku który - gdy kliknięty przez administratora - wykona dowolną operację na stronie którą może wykonać administrator (taką jak np. modyfikację treści).",
    "XNAT contains an admin default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.": "Wykryto, że narzędzie XNAT umożliwia logowanie za pomocą domyślnej nazwy użytkownika i hasła. Atakujący może uzyskać dostęp do kont użytkowników, pobrać wrażliwe dane, zmienić dane lub wykonywać nieuprawnione operacje.",
    "IBM Eclipse Help System 6.1.0 through 6.1.0.6, 6.1.5 through 6.1.5.3, 7.0 through 7.0.0.2, and 8.0 prior to 8.0.0.1 contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site.": "IBM Eclipse Help System w wersji od 6.1.0 do 6.1.0.6, 6.1.5 do 6.1.5.3, 7.0 do 7.0.0.2 i 8.0 poniżej 8.0.0.1 zawiera podatność Cross-Site Scripting umożliwiającą atakującemu spreparowanie linku który - gdy kliknięty przez administratora - wykona dowolną operację na stronie którą może wykonać administrator (taką jak np. modyfikację treści).",
    "The takeover will succeed when the target domain has a cname that points to the lemlist and in their account they only customize the domain in the tracking column so in the custom page column, as an attacker, they can enter the target domain.": "Wykryto domenę skonfigurowaną, aby serwować treści z narzędzia lemlist, ale strona docelowa nie istnieje i potencjalnie, w niektórych przypadkach, może być przejęta przez atakującego. Jeśli domena nie jest używana, rekomendujemy jej usunięcie.",
    "Joomla! com_booking component suffers from Information leak vulnerability in which sensitive or confidential data is unintentionally exposed or made accessible to unauthorized individuals or systems.": "Komponent Joomla! o nazwie com_booking w wersji 2.4.9 zawiera podatność Information Leak umożliwiającą atakującym pobranie wrażliwych danych."
    + UPDATE_HINT,
    "http/misconfiguration/springboot/springboot-trace.yaml": "Wykryto końcówkę systemu Spring Boot umożliwiającą podgląd żądań i odpowiedzi HTTP, które mogą zawierać dane wrażliwe. Rekomendujemy, aby takie końcówki nie były dostępne publicznie.",
    "http/misconfiguration/springboot/springboot-dump.yaml": "Wykryto końcówkę systemu Spring Boot umożliwiającą podgląd wątków uruchomionych w systemie. Rekomendujemy, aby takie końcówki nie były dostępne publicznie.",
    "A local file inclusion vulnerability in Accent Microcomputers offerings could allow remote attackers to retrieve password files.": "Wykryto podatność Local File Inclusion w oprogramowaniu Accent Microcomputers umożliwiającą atakującemu odczyt dowolnych plików z dysku.",
    "http/exposures/configs/zend-config-file.yaml": "Wykryto plik konfiguracyjny systemu Zend zawierający dane logowania do bazy danych."
    + DATA_HIDE_HINT,
    "WordPress FlagEm plugin contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Wykryto, że wtyczka WordPress o nazwie FlagEm zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "WordPress Adaptive Images < 0.6.69 is susceptible to cross-site scripting because the plugin does not sanitize and escape the REQUEST_URI before outputting it back in a page.": "Wtyczka WordPress o nazwie Adaptive Images w wersji poniżej 0.6.69 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "Tiki Wiki CMS Groupware 5.2 contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Tiki Wiki CMS Groupware w wersji 5.2 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "WordPress Slideshow plugin contains multiple cross-site scripting vulnerabilities. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Wykryto, że wtyczka WordPress o nazwie Slideshow zawiera podatności typu Cross-Site Scripting umożliwiające atakującemu spreparowanie linku, który, gdy zostanie kliknięty przez administratora, wykona dowolną akcję z jego uprawnieniami (taką jak np. modyfikację treści)."
    + WORDPRESS_UPDATE_HINT,
    "Qcubed contains a cross-site scripting vulnerability which allows a remote attacker to inject arbitrary JavaScript via the /assets/php/_devtools/installer/step_2.php endpoint and the installation_path parameter.": "Wykryto, że narzędzie Qcubed zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "WordPress Custom Tables 3.4.4 plugin contains a cross-site scripting vulnerability via the key parameter.": "Wtyczka WordPress o nazwie Custom Tables w wersji 3.4.4 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "Cross-site scripting vulnerability was discovered.": "Wykryto podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "WordPress NextGEN Gallery 1.9.10 plugin contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Wtyczka WordPress o nazwie NextGEN Gallery w wersji 1.9.10 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "Netsweeper 4.0.9 contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Narzędzie Netsweeper w wersji 4.0.9 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "WordPress PHPFreeChat 0.2.8 plugin contains a cross-site scripting vulnerability via the url parameter. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Wtyczka WordPress o nazwie PHPFreeChat w wersji 0.2.8 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "WordPress Plugin Finder contains a cross-site scripting vulnerability via the order parameter. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Wykryto, że wtyczka WordPress Plugin Finder zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "http/exposures/files/core-dump.yaml": "Wykryto plik core dump, mogący zawierać wrażliwe dane." + DATA_HIDE_HINT,
    "http/vulnerabilities/other/erensoft-sqli.yaml": "Wykryto podatność SQL Injection w narzędziu ErenSoft, która może umożliwić atakującemu pobranie dowolnych danych z bazy danych."
    + UPDATE_HINT,
    "The Integrate Google Drive plugin for WordPress is vulnerable to unauthorized access due to a missing capability check on several REST API endpoints in versions up to, and including, 1.1.99. This makes it possible for unauthenticated attackers to perform a wide variety of operations, such as moving files, creating folders, copying details, and much more.": "Wtyczka WordPress o nazwie Integrate Google Drive w wersjach do 1.1.99 zawiera podatność umożliwiającą atakującemu nieuprawnione wykonywanie operacji takich jak np. pobieranie informacji, przenoszenie plików itp."
    + WORDPRESS_UPDATE_HINT,
    "http/misconfiguration/installer/webcalendar-install.yaml": "Wykryto dostępny publicznie instalator systemu WebCalendar, dający atakującemu możliwość wprowadzenia własnej konfiguracji i przejęcia kontroli nad systemem. Rekomendujemy, aby takie zasoby nie były dostępne publicznie.",
    "Detects exposed CMS Made Simple Installation page.": "Wykryto dostępny publicznie instalator systemu CMS Made Simple, dający atakującemu możliwość wprowadzenia własnej konfiguracji i przejęcia kontroli nad systemem. Rekomendujemy, aby takie zasoby nie były dostępne publicznie.",
    "Drupal Install panel exposed.": "Wykryto dostępny publicznie instalator systemu Drupal, dający atakującemu możliwość wprowadzenia własnej konfiguracji i przejęcia kontroli nad systemem. Rekomendujemy, aby takie zasoby nie były dostępne publicznie.",
    "A source code disclosure vulnerability in a web server caused by improper handling of multiple requests in quick succession, leading to the server treating requested files as static files instead of executing scripts.": "Serwer deweloperski udostępniany przez język programowania PHP w wersjach do 7.4.21 włącznie zawiera podatność umożliwiającą atakującemu nieuprawniony odczyt kodu źródłowego."
    + UPDATE_HINT,
    "GoIP-1 GSM is vulnerable to local file inclusion because input passed thru the 'content' or 'sidebar' GET parameter in 'frame.html' or 'frame.A100.html' is not properly sanitized before being used to read files. This can be exploited by an unauthenticated attacker to read arbitrary files on the affected system.": "Wykryto, że GoIP-1 GSM zawiera podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików z serwera.",
    "Execution After Redirect happens when after emitting a Location header that redirects the user, some other code is executed. This may lead to data leak or application compromise.": "Wykryto podatność Execution After Redirect, czyli sytuację, gdy serwer, pomimo przekierowania użytkownika na inny adres, kontynuuje wykonanie skryptu. Może to doprowadzić do wycieku wrażliwych danych lub uzyskania przez atakującego nieuprawnionego dostępu do aplikacji.",
    "[no description] http/misconfiguration/django-debug-detect.yaml": "Wykryto system Django w konfiguracji debug. Upublicznienie systemu w takiej konfiguracji może umożliwić atakującemu poznanie informacji na temat działania aplikacji lub jej konfiguracji.",
    "Rails debug mode is enabled.": "Wykryto framework Rails w konfiguracji debug. Upublicznienie systemu w takiej konfiguracji może umożliwić atakującemu poznanie informacji na temat działania aplikacji lub jej konfiguracji.",
    "Django debug configuration is enabled, which allows an attacker to obtain system configuration information such as paths or settings.": "Wykryto system Django w konfiguracji debug. Upublicznienie systemu w takiej konfiguracji może umożliwić atakującemu poznanie informacji na temat działania aplikacji lub jej konfiguracji.",
    "Unauthenticated PostgreSQL Detected.": "Wykryto system PostgreSQL, do którego można zalogować się bez uwierzytelniania.",
    "Detect Postgresql Version.": "Wykryto system PostgreSQL, w którym można wykonywać niektóre polecenia bez uwierzytelniania.",
    "Laravel with APP_DEBUG set to true is prone to show verbose errors.": "Wykryto system Laravel w konfiguracji debug. Upublicznienie systemu w takiej konfiguracji może umożliwić atakującemu poznanie informacji na temat działania aplikacji lub jej konfiguracji.",
    "DOMPDF Configuration page was detected, which contains paths, library versions and other potentially sensitive information": "Wykryto stronę konfiguracyjną DOMPDF, która zawiera ścieżki, wersje zainstalowanego oprogramowania i inne potencjalnie wrażliwe informacje.",
    "This check detects if there are any active content loaded over HTTP instead of HTTPS.": "Wykryto, że zasoby takie jak skrypty są ładowane za pomocą nieszyfrowanego połączenia. Może to umożliwić atakującemu ich podmianę, a w konsekwencji zmianę wyglądu lub zachowania strony.",
    "OwnCloud is susceptible to the Installation page exposure due to misconfiguration.": "wykryto, że panel instalacyjny narzędzia OwnCloud jest publicznie dostępny, co może umożliwić atakującemu nieuprawniony dostęp do systemu.",
    "phpMyAdmin contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.": "Wykryto, że do systemu phpMyAdmin można zalogować się prostym hasłem. Atakujący może uzyskać dostęp do kont użytkowników czy wrażliwych danych, zmienić dane lub wykonać nieuprawnione operacje.",
    "phpMyAdmin panel was detected.": "wykryto panel logowania narzędzia phpMyAdmin.",
    "netlify takeover was detected.": "Wykryto domenę skonfigurowaną, aby serwować treści z narzędzia Netlify, ale strona docelowa nie istnieje. Atakujący może utworzyć taką stronę w serwisie Netlify, aby serwować swoje treści. Jeśli domena nie jest używana, rekomendujemy jej usunięcie.",
    "Tilda takeover was detected.": "Wykryto domenę skonfigurowaną, aby serwować treści z narzędzia Tilda, ale strona docelowa nie istnieje. Atakujący może utworzyć taką stronę w serwisie Tilda, aby serwować swoje treści. Jeśli domena nie jest używana, rekomendujemy jej usunięcie.",
    "shopify takeover was detected.": "Wykryto domenę skonfigurowaną, aby serwować treści z narzędzia Shopify, ale strona docelowa nie istnieje. Atakujący może utworzyć taką stronę w serwisie Shopify, aby serwować swoje treści. Jeśli domena nie jest używana, rekomendujemy jej usunięcie.",
    "auth.json file is exposed.": "Wykryto plik auth.json, zawierający login i hasło lub inne dane autoryzacyjne. Rekomendujemy, aby takie dane nie były dostępne publicznie.",
    "Django Debug Method is enabled.": "Wykryto framework Django skonfigurowany aby udostępniać informacje diagnostyczne, takie jak konfiguracja systemu czy ścieżki.",
    "[no description] http/vulnerabilities/generic/cors-misconfig.yaml": "Wykryto, że nagłówki Access-Control-Allow-Origin i Access-Control-Allow-Credentials są skonfigurowane w sposób umożliwiający innym stronom odczyt plików cookie, co może skutkować nieuprawnionym dostępem do systemu.",
    "Remote Code Execution in PAN-OS 7.1.18 and earlier, PAN-OS 8.0.11-h1 and earlier, and PAN-OS 8.1.2 and earlier with GlobalProtect Portal or GlobalProtect Gateway Interface enabled may allow an unauthenticated remote attacker to execute arbitrary code.": "PAN-OS w wersji 7.1.18 i wcześniejszych, 8.0.11-h1 i wcześniejszych oraz 8.1.2 i wcześniejszych z włączonymi modułami GlobalProtect Portal lub GlobalProtect Gateway Interface mogą umożliwiać atakującym zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Selenium was shown to have an exposed node. If a Selenium node is exposed without any form of authentication, remote command execution could be possible if chromium is configured. By default the port is 4444, still, most of the internet facing are done through reverse proxies.": "Wykryto publicznie dostępny węzeł narzędzia Selenium, potencjalnie umożliwiający atakującemu zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION,
    'HTTP.sys in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows remote attackers to execute arbitrary code via crafted HTTP requests, aka "HTTP.sys Remote Code Execution Vulnerability."': "Implementacja serwera internetowego HTTP.sys w systemach Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8, Windows 8.1 i Windows Server 2012 Gold i R2 umożliwia atakującym zdalne wykonanie kodu przy użyciu spreparowanych żądań HTTP."
    + UPDATE_HINT,
    "Internal information is exposed in elasticsearch to external users.": "Wykryto konfigurację lub dane systemu Elasticsearch dostępne bez logowania."
    + DATA_HIDE_HINT,
    "Remote code execution vulnerability in Telerik ASP.NET AJAX version before 2017.2.711": "Wykryto podatność w oprogramowaniu Telerik ASP.NET AJAX w wersji poniżej 2017.2.711 umożliwiającą zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "A misconfiguration in Gitea allows arbitrary users to sign up and read code hosted on the service.": "Wykryto serwis Gitea, którego konfiguracja umożliwia nowym użytkownikom rejestrację, co może dać atakującemu dostęp do kodu źródłowego przechowywanego w serwisie.",
    "JBoss JMX Console default login information was discovered.": "wykryto, że do panelu JBoss JMX Console można zalogować się domyślnymi danymi."
    + DEFAULT_CREDENTIALS_HINT,
    "Apache ActiveMQ default login information was discovered.": "wykryto, że do panelu Apache ActiveMQ Console można zalogować się domyślnymi danymi."
    + DEFAULT_CREDENTIALS_HINT,
    "SiteCore 9.3 is vulnerable to LFI.": "Narzędzie SiteCore w wersji 9.3 zawiera podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików z dysku."
    + UPDATE_HINT,
    "WordPress `wp-config` was discovered. This file is remotely accessible and its content available for reading.": "Wykryto kopię zapasową pliku `wp-config`, która może zawierać np. dane do logowania do bazy danych, umożliwiające atakującemu przejęcie pełnej kontroli nad systemem."
    + DATA_HIDE_HINT,
    "ISPConfig Default Password Vulnerability exposes systems to unauthorized access, compromising data integrity and security.": "wykryto, że do panelu ISPConfig można zalogować się domyślnym hasłem, co umożliwia atakującemu nieuprawniony dostęp do systemu.",
    "ACTI video surveillance has loopholes in reading any files": "Wykryto, że system Acti-Video Monitoring zawiera podatność umożliwiającą odczyt dowolnych plików z serwera.",
    "Jolokia is vulnerable to local file inclusion via compilerDirectivesAdd.": "wykryto wersję systemu Jolokia zawierającą podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku.",
    "CVE-2024-24919 is an information disclosure vulnerability that can allow an attacker to access certain information on internet-connected Gateways which have been configured with IPSec VPN, remote access VPN or mobile access software blade.": "Wykryto podatność CVE-2024-24919 w urządzeniu Check Point Quantum Gateway umożliwiającą atakującemu odczyt dowolnych plików z dysku.",
    "ELMAH (Error Logging Modules and Handlers) is an application-wide error logging facility that is completely pluggable. It can be dynamically added to a running ASP.NET web application, or even all ASP.NET web applications on a machine, without any need for re-compilation or re-deployment. In some cases, the logs expose ASPXAUTH cookies allowing to hijack a logged in administrator session.": "Wykryto, że dziennik zdarzeń udostępniany przez moduł ELMAH (Error Logging Modules and Handlers) jest publicznie dostępny. W niektórych sytuacjach może on zawierać informacje umożliwiające przejęcie zalogowanej sesji administratora.",
    "Checks websites for Balada Injector malware.": "Wykryto, że strona jest zainfekowana złośliwym oprogramowaniem Balada Injector.",
    "WS_FTP software, which is a popular FTP (File Transfer Protocol) client used for transferring files between a local computer and a remote server has its log file exposed.": "Wykryto dziennik zdarzeń oprogramowania WS_FTP.",
    "[no description] http/exposed-panels/compalex-panel-detect.yaml": "Wykryto panel Compalex.",
    "Joomla is susceptible to the Installation page exposure due to misconfiguration.": "Wykryto publicznie dostępny panel instalacyjny systemu Joomla.",
    "Exposed Wordpress Setup Configuration.": "Wykryto publicznie dostępny panel instalacyjny systemu WordPress.",
    "Error log files were exposed.": "Wykryto publicznie dostępny dziennik zdarzeń serwera HTTP." + DATA_HIDE_HINT,
    "WordPress Accessibility Helper plugin before 0.6.0.7 contains a cross-site scripting vulnerability. It does not sanitize and escape the wahi parameter before outputting back its base64 decode value in the page.": "Wtyczka WordPress o nazwie Accessibility Helper w wersji poniżej 0.6.0.7 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "WordPress Elementor Website Builder plugin 3.5.5 and prior contains a reflected cross-site scripting vulnerability via the document object model.": "Wtyczka WordPress o nazwie Elementor Website Builder w wersji 3.5.5 i wcześniejszych zawiera podatność Cross-Site Scripting."
    + WORDPRESS_UPDATE_HINT,
    "Multiple compressed backup files were detected.": "Wykryto publicznie dostępny plik kopii zapasowej."
    + DATA_HIDE_HINT,
    "Multiple Docker Compose configuration files were detected. The configuration allows deploy, combine and configure operations on multiple containers at the same time. The default is to outsource each process to its own container, which is then publicly accessible.": "Wykryto pliki konfiguracyjne Docker Compose, umożliwiające atakującemu poznanie konfiguracji aplikacji."
    + DATA_HIDE_HINT,
    "An open redirect vulnerability was detected. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.": "Wykryto podatność typu Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie.",
    "Odoo CMS contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.": "Wykryto system Odoo CMS zawierający podatność typu Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie.",
    "Apache Tomcat versions prior to 9.0.12, 8.5.34, and 7.0.91 are prone to an open-redirection vulnerability because it fails to properly sanitize user-supplied input.": "System Apache Tomcat w wersji poniżej 9.0.12, w gałęzi 8 w wersji poniżej 8.5.34 i w gałęzi 7 w wersji poniżej 7.0.91 zawiera podatność typu Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie."
    + UPDATE_HINT,
    "WordPress WPtouch plugin 3.x contains an open redirect vulnerability. The plugin fails to properly sanitize user-supplied input. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.": "Wtyczka WordPress o nazwie WPtouch w wersji 3.x zawiera podatność typu Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie."
    + WORDPRESS_UPDATE_HINT,
    "WordPress WPtouch 3.7.5 is affected by an Open Redirect issue.": "Wtyczka WordPress o nazwie WPtouch w wersji 3.7.5 zawiera podatność typu Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie."
    + WORDPRESS_UPDATE_HINT,
    "WordPress All-in-One Security plugin through 4.4.1 contains an open redirect vulnerability which can expose the actual URL of the hidden login page feature. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.": "Wtyczka WordPress o nazwie All-in-One Security plugin w wersji do 4.4.1 zawiera podatność typu Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie."
    + WORDPRESS_UPDATE_HINT,
    "HomeAutomation 3.3.2 contains an open redirect vulnerability. An attacker can inject a redirect URL via the api.php endpoint and the redirect parameter, making it possible to redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.": "Wykryto, że narzędzie HomeAutomation zawiera podatność typu Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie.",
    "A Joomla! database directory /libraries/joomla/database/ was found exposed and has directory indexing enabled.": "Wykryto listing plików w katalogu /libraries/joomla/database/. "
    + DIRECTORY_INDEX_HINT,
    "A MySQL dump file was found": "Wykryto zrzut bazy danych MySQL." + DATA_HIDE_HINT,
    "WordPress theme with a 'Mega-Theme' design is vulnerable to a reflected XSS attack through the '?s=' parameter.": "Wykryto, że szablon WordPress oparty na Mega-Theme zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION,
    "AppServ Open Project 2.5.10 and earlier contains a cross-site scripting vulnerability in index.php which allows remote attackers to inject arbitrary web script or HTML via the appservlang parameter.": "AppServ Open Project w wersji 2.5.10 i wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "An ioncube Loader Wizard was discovered.": "Wykryto narzędzie ioncube Loader Wizard. Rekomendujemy, aby takie zasoby nie były publicznie dostępne.",
    "Multiple phpMyAdmin setup files were detected.": "Wykryto pliki instalacyjne systemu phpMyAdmin. Rekomendujemy, aby takie zasoby nie były publicznie dostępne.",
    "Webalizer log analyzer configuration was detected.": "Wykryto konfigurację analizera logów Webalizer."
    + DATA_HIDE_HINT,
    "Multiple NETGEAR router models disclose their serial number which can be used to obtain the admin password if password recovery is enabled.": "Wykryto router NETGEAR skonfigurowany, aby udostępniać dane takie jak numer seryjny, które w niektórych sytuacjach wystarczają do odzyskania hasła administratora.",
    "CVE-2024-24919 is an information disclosure vulnerability that can allow an attacker to access certain information on internet-connected Gateways which have been configured with IPSec VPN, remote access VPN, or mobile access software blade.": "Wykryto urządzenie CheckPoint w wersji, która zawiera podatność Directory Traversal, umożliwiającą atakującemu odczyt dowolnych plików z dysku.",
    "HAProxy statistics page was detected.": "Wykryto stronę ze statystykami systemu HAProxy.",
    "This template can be used to detect a Laravel debug information leak by making a POST-based request.": "Wykryto, że za pomocą żądania POST można odczytać konfigurację systemu Laravel, zawierającą dane dostępowe do bazy danych.",
    "Test CGI script was detected. Response page returned by this CGI script exposes a list of server environment variables.": "Wykryto skrypt CGI udostępniający publicznie konfigurację serwera.",
    "Obsolete and insecure SmodBIP system was detected. In Poland the system is not recommended to be used by the Government Plenipotentiary for Cybersecurity.": "Wykryto system SmodBIP, który nie jest już utrzymywany i zawiera znane podatności, np. CVE-2023-4837. W dniu 12 czerwca 2024 Pełnomocnik Rządu ds. Cyberbezpieczeństwa wydał rekomendację niestosowania systemów SmodBIP i MegaBIP.",
    "MegaBIP system was detected, which (in Poland) is not recommended to be used by the Government Plenipotentiary for Cybersecurity. The recommendation concerns all versions of the software.": "Wykryto system MegaBIP. W dniu 12 czerwca 2024 Pełnomocnik Rządu ds. Cyberbezpieczeństwa wydał rekomendację niestosowania systemów SmodBIP i MegaBIP. Rekomendacja dotyczy wszystkich wersji systemu MegaBIP.",
    "phpMyAdmin before 4.9.0 is susceptible to cross-site request forgery. An attacker can utilize a broken <img> tag which points at the victim's phpMyAdmin database, thus leading to potential delivery of a payload, such as a specific INSERT or DELETE statement.": "Narzędzie phpMyAdmin w wersji poniżej 4.9.0 zawiera podatność Cross-Site Request Forgery umożliwiającą atakujacemu spreparowanie linku, który - gdy odwiedzony przez zalogowanego użytkownika - wykona zmianę w bazie danych."
    + UPDATE_HINT,
    "A Password in Configuration File issue was discovered in Dahua DH-IPC-HDBW23A0RN-ZS, DH-IPC-HDBW13A0SN, DH-IPC-HDW1XXX, DH-IPC-HDW2XXX, DH-IPC-HDW4XXX, DH-IPC-HFW1XXX, DH-IPC-HFW2XXX, DH-IPC-HFW4XXX, DH-SD6CXX, DH-NVR1XXX, DH-HCVR4XXX, DH-HCVR5XXX, DHI-HCVR51A04HE-S3, DHI-HCVR51A08HE-S3, and DHI-HCVR58A32S-S2 devices. The password in configuration file vulnerability was identified, which could lead to a malicious user assuming the identity of a privileged user and gaining access to sensitive information.": "Wykryto publicznie dostępny plik konfiguracyjny urządzenia Dahua DH-IPC-HDBW23A0RN-ZS, DH-IPC-HDBW13A0SN, DH-IPC-HDW1XXX, DH-IPC-HDW2XXX, DH-IPC-HDW4XXX, DH-IPC-HFW1XXX, DH-IPC-HFW2XXX, DH-IPC-HFW4XXX, DH-SD6CXX, DH-NVR1XXX, DH-HCVR4XXX, DH-HCVR5XXX, DHI-HCVR51A04HE-S3, DHI-HCVR51A08HE-S3 lub DHI-HCVR58A32S-S2 zawierający hasło. Korzystając z tego hasła, atakujący może uzyskać uprawnienia uprzywilejowanego użytkownika i uzyskać dostęp do wrażliwych informacji.",
    "TP-LINK is susceptible to local file inclusion in these products: Archer C5 (1.2) with firmware before 150317, Archer C7 (2.0) with firmware before 150304, and C8 (1.0) with firmware before 150316, Archer C9 (1.0), TL-WDR3500 (1.0), TL-WDR3600 (1.0), and TL-WDR4300 (1.0) with firmware before 150302, TL-WR740N (5.0) and TL-WR741ND (5.0) with firmware before 150312, and TL-WR841N (9.0), TL-WR841N (10.0), TL-WR841ND (9.0), and TL-WR841ND (10.0) with firmware before 150310.  Because of insufficient input validation, arbitrary local files can be disclosed. Files that include passwords and other sensitive information can be accessed.": "Wykryto router TP-LINK Archer C5 (1.2) w wersji firmware poniżej 150317, Archer C7 (2.0) w wersji firmware poniżej 150304, C8 (1.0) w wersji firmware poniżej 150316, Archer C9 (1.0), TL-WDR3500 (1.0), TL-WDR3600 (1.0) lub TL-WDR4300 (1.0) w wersji firmware poniżej 150302, TL-WR740N (5.0) lub TL-WR741ND (5.0) w wersji firmware poniżej 150312, TL-WR841N (9.0), TL-WR841N (10.0), TL-WR841ND (9.0) lub TL-WR841ND (10.0) w wersji firmware poniżej 150310 zawierający podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików, w tym np. konfiguracyjnych zawierających wrażliwe informacje.",
    "Leaked session of Wpdm Cache wordpress plugin.": "Wykryto pamięć podręczną wtyczki WordPress o nazwie Wpdm Cache, mogącą zawierać dane umożliwiające przejęcie sesji zalogowanego użytkownika.",
    "WordPress Page Builder KingComposer 2.9.6 and prior does not validate the id parameter before redirecting the user to it via the kc_get_thumbn AJAX action (which is available to both unauthenticated and authenticated users).": "Wtyczka WordPress o nazwie Page Builder KingComposer w wersji 2.9.6 i wcześniejszych zawiera podatność Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie."
    + WORDPRESS_UPDATE_HINT,
    "Jolokia - Information is exposed.": "Wykryto publicznie dostępne informacje diagnostyczne systemu Jolokia."
    + DATA_HIDE_HINT,
    "Oracle CGI printenv component is susceptible to an information disclosure vulnerability.": "Wykryto publicznie dostępny plik CGI printenv, udostępniający konfigurację aplikacji. Rekomendujemy, aby takie zasoby nie były dostępne publicznie.",
    "The plugin does not restrict access to published and non protected posts/pages when the maintenance mode is enabled, allowing unauthenticated users to access them.": "Wtyczka WordPress o nazwie CMP – Coming Soon & Maintenance Plugin w wersji poniżej 4.1.6 umożliwia odczyt treści pomimo włączonego trybu konserwacji."
    + WORDPRESS_UPDATE_HINT,
    "SourceBans before 2.0 contains a cross-site scripting vulnerability which allows remote attackers to inject arbitrary web script or HTML via the advSearch parameter to index.php.": "System SourceBeans w wersji poniżej 2.0 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "The POST SMTP Mailer  Email log, Delivery Failure Notifications and Best Mail SMTP for WordPress plugin for WordPress is vulnerable to unauthorized access of data and modification of data due to a type juggling issue on the connect-app REST endpoint in all versions up to, and including, 2.8.7.": "Wtyczka WordPress o nazwie POST SMTP Mailer  Email log, Delivery Failure Notifications and Best Mail SMTP for WordPress w wersji 2.8.7 i niższych umożliwia atakującemu nieuprawniony dostęp do informacji."
    + WORDPRESS_UPDATE_HINT,
    "Nova noVNC contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.": "Wykryto, że system Nova noVNC zawiera podatność typu Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie.",
    "An issue was discovered in ownCloud owncloud/graphapi 0.2.x before 0.2.1 and 0.3.x before 0.3.1. The graphapi app relies on a third-party GetPhpInfo.php library that provides a URL. When this URL is accessed, it reveals the configuration details of the PHP environment (phpinfo). This information includes all the environment variables of the webserver. In containerized deployments, these environment variables may include sensitive data such as the ownCloud admin password, mail server credentials, and license key. Simply disabling the graphapi app does not eliminate the vulnerability. Additionally, phpinfo exposes various other potentially sensitive configuration details that could be exploited by an attacker to gather information about the system.": "Biblioteka owncloud/graphapi w wersji 0.2.x poniżej 0.2.1 i 0.3.x poniżej 0.3.1 zawiera podatność umożliwiającą odczyt konfiguracji serwera."
    + UPDATE_HINT,
    "An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.": "Wykryto podatność w systemie Joomla! w wersji od 4.0.0 do 4.2.7 umożliwiającą atakującemu odczyt wrażliwych informacji na temat użytkowników."
    + UPDATE_HINT,
    "The Frontend Uploader WordPress plugin prior to v.0.9.2 was affected by an unauthenticated Cross-Site Scripting security vulnerability.": "Wtyczka WordPress o nazwie Frontend Uploader w wersji poniżej 0.9.2 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "WordPress Newspaper theme before 12 is susceptible to cross-site scripting. The does not sanitize a parameter before outputting it back in an HTML attribute via an AJAX action. An attacker can potentially execute malware, obtain sensitive information, modify data, and/or execute unauthorized operations without entering necessary credentials.": "Szablon WordPress o nazwie Newspaper w wersji poniżej 12 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "Grafana 3.0.1 through 7.0.1 is susceptible to server-side request forgery via the avatar feature, which can lead to remote code execution. Any unauthenticated user/client can make Grafana send HTTP requests to any URL and return its result. This can be used to gain information about the network Grafana is running on, thereby potentially enabling an attacker to obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.": "System Grafana w wersji od 3.0.1 do 7.0.1 zawiera podatność /CVE-2020-13379 która w niektórych sytuacjach może prowadzić do zdalnego wykonania kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    'JavaMelody is a tool used to monitor Java or Java EE applications in QA and production environments. JavaMelody was detected on this web application. One option in the dashboard is to "View http sessions". This can be used by an attacker to steal a user\'s session.': "Wykryto publicznie dostępny system JavaMelody, za pomocą którego atakujący może przejąć sesję zalogowanego użytkownika. Rekomendujemy, aby takie zasoby nie były dostępne publicznie.",
    "Visual Studio Code directories were detected.": "Wykryto katalogi z informacjami środowiska programistycznego Visual Studio Code."
    + DATA_HIDE_HINT,
    "Dockerfile was detected.": "Wykryto plik Dockerfile." + DATA_HIDE_HINT,
    "SAP Solution Manager contains an open redirect vulnerability via the logoff endpoint. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.": "Wykryto, że system SAP Solution Manager zawiera podatność Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie.",
    "WordPress Transposh Translation plugin before 1.0.8 contains a reflected cross-site scripting vulnerability. It does not sanitize and escape the a parameter via an AJAX action (available to both unauthenticated and authenticated users when the curl library is installed) before outputting it back in the response.": "Wtyczka WordPress o nazwie Transposh Translation w wersji poniżej 1.0.8 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "Zarafa WebApp 2.0.1.47791 and earlier contains an unauthenticated reflected cross-site scripting vulnerability. An attacker can execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site.": "Zarafa WebApp w wersji 2.0.1.47791 i wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "WordPress HC Custom WP-Admin URL plugin through 1.4 leaks the secret login URL when sending a specially crafted request, thereby allowing an attacker to discover the administrative login URL.": "Wtyczka WordPress o nazwie HC Custom WP-Admin URL w wersji do 1.4 włącznie zawiera podatność umożliwiającą atakującemu poznanie adresu panelu logowania, nawet jak został zmieniony w stosunku do domyślnego."
    + WORDPRESS_UPDATE_HINT,
    "TileServer GL through 3.0.0 is vulnerable to reflected cross-site scripting via server.js  because the content of the key GET parameter is reflected unsanitized in an HTTP response for the application's main page.": "Narzędzie TileServer GL w wersji do 3.0.0 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "zabbix-dashboards-access guest login credentials were successful.": "Logowanie kontem gościa do panelu systemu Zabbix jest możliwe.",
    "The Defender Security WordPress plugin before 4.1.0 does not prevent redirects to the login page via the auth_redirect WordPress function, allowing an unauthenticated visitor to access the login page, even when the hide login page functionality of the plugin is enabled.": "Wtyczka WordPress o nazwie Defender Security w wersji poniżęj 4.1.0 umożliwia atakującemu dostęp do panelu logowania nawet, jeśli funkcja ukrywania panelu logowania jest włączona."
    + WORDPRESS_UPDATE_HINT,
    "CLink Office 2.0 is vulnerable to cross-site scripting in the index page of the management console and allows remote attackers to inject arbitrary web script or HTML via the lang parameter.": "Clink Office w wersji 2.0 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Adminer 4.6.1 to 4.8.0 contains a cross-site scripting vulnerability which affects users of MySQL, MariaDB, PgSQL, and SQLite in browsers without CSP when Adminer uses a `pdo_` extension to communicate with the database (it is used if the native extensions are not enabled).": "Adminer w wersji od 4.6.1 do 4.8.0 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "The plugin does not validate that the event_id parameter in its eventon_ics_download ajax action is a valid Event, allowing unauthenticated visitors\nto access any Post (including unpublished or protected posts) content via the ics export functionality by providing the numeric id of the post.": "Wtyczka WordPress o nazwie EventON Calendar w wersji 4.4 i niższych umożliwia atakującemu odczyt niepublicznych postów i postów chronionych hasłem."
    + WORDPRESS_UPDATE_HINT,
    "The EventON WordPress plugin before 4.5.5, EventON WordPress plugin before 2.2.7 do not have authorization in an AJAX action, allowing unauthenticated users to retrieve email addresses of any users on the blog.": "Wtyczka WordPress o nazwie EventON Calendar w wersji poniżej 4.5.5 umożliwia atakującemu odczyt adresów e-mail użytkowników."
    + WORDPRESS_UPDATE_HINT,
    "The EventON WordPress plugin before 2.1.2 lacks authentication and authorization in its eventon_ics_download ajax action, allowing unauthenticated visitors to access private and password protected Events by guessing their numeric id.": "Wtyczka WordPress o nazwie EventON Calendar w wersji 2.1.2 i niższych umożliwia atakującemu odczyt niepublicznych wydarzeń i wydarzeń chronionych hasłem."
    + WORDPRESS_UPDATE_HINT,
    "XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Users are able to forge an URL with a payload allowing to inject Javascript in the page (XSS). It's possible to exploit the DeleteApplication page to perform a XSS, e.g. by using URL such as: > xwiki/bin/view/AppWithinMinutes/DeleteApplication?appName=Menu&resolve=true&xredirect=javascript:alert(document.domain). This vulnerability exists since XWiki 6.2-milestone-1. The vulnerability has been patched in XWiki 14.10.5 and 15.1-rc-1.": "System XWiki w wersji do 14.10.5 (w gałęzi 14) i 15.1-rc-1 (w gałęzi 15) zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Wordpress Wordfence is vulnerable to cross-site scripting.": "Wykryto wtyczkę WordPress o nazwie Wordfence w wersji zawierającej podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "WorsPress Spider Calendar plugin through 1.5.65 is susceptible to cross-site scripting. The plugin does not sanitize and escape the callback parameter before outputting it back in the page via the window AJAX action, available to both unauthenticated and authenticated users. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Wtyczka WordPress o nazwie Spider Calendar w wersji do 1.5.65 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "The Duplicator WordPress plugin before 1.5.7.1, Duplicator Pro WordPress plugin before 4.5.14.2 does not disallow listing the `backups-dup-lite/tmp` directory (or the `backups-dup-pro/tmp` directory in the Pro version), which temporarily stores files containing sensitive data. When directory listing is enabled in the web server, this allows unauthenticated attackers to discover and access these sensitive files, which include a full database dump and a zip archive of the site.": "Wykryto wtyczkę WordPress o nazwie Duplicator w wersji poniżej 1.5.7.1 i serwer z włączonym listingiem katalogów, w tym katalogu backups-dup-lite/tmp lub backups-dup-pro/tmp, gdzie znajdują się pliki tymczasowe używane przy tworzeniu kopii zapasowej. Atakujący może odczytać taki plik w chwili gdy tworzona jest kopia zapasowa, a w ten sposób uzyskać pełen dostęp np. do zrzutu bazy danych strony internetowej.",
    "http/vulnerabilities/wordpress/unauthenticated-duplicator-disclosure.yaml": "Wykryto wtyczkę WordPress o nazwie Duplicator w wersji poniżej 1.5.7.1 i serwer z włączonym listingiem katalogów, w tym katalogu backups-dup-lite/tmp lub backups-dup-pro/tmp, gdzie znajdują się pliki tymczasowe używane przy tworzeniu kopii zapasowej. Atakujący może odczytać taki plik w chwili gdy tworzona jest kopia zapasowa, a w ten sposób uzyskać pełen dostęp np. do zrzutu bazy danych strony internetowej.",
    'Django 1.10.x before 1.10.8 and 1.11.x before 1.11.5 has HTML autoescaping  disabled in a portion of the template for the technical 500 debug page. Given the right circumstances, this allows a cross-site scripting attack. This vulnerability shouldn\'t affect most production sites since run with "DEBUG = True" is not on by default (which is what makes the page visible).': "Wykryto system Django 1.10.x w wersji poniżej 1.10.8 lub 1.11.x w wersji poniżej 1.11.5, który, gdy jest włączony tryb DEBUG (a taki tryb wykryto na badanej stronie), zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Django 1.10.x before 1.10.8 and 1.11.x before 1.11.5 has HTML autoescaping disabled in a portion of the template for the technical 500 debug page. We detected that right circumstances (DEBUG=True) are present to allow a cross-site scripting attack.": "Wykryto system Django 1.10.x w wersji poniżej 1.10.8 lub 1.11.x w wersji poniżej 1.11.4, który, gdy jest włączony tryb DEBUG (a taki tryb wykryto na badanej stronie), zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Jenkins Gitlab Hook 1.4.2 and earlier does not escape project names in the build_now endpoint, resulting in a reflected cross-site scripting vulnerability.": "Wtyczka Jenkins o nazwie Gitlab Hook w wersji 1.4.2 i wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "WordPress Visual Form Builder plugin before 3.0.8 contains a cross-site scripting vulnerability. The plugin does not perform access control on entry form export, allowing an unauthenticated user to export the form entries as CSV files using the vfb-export endpoint.": "Wtyczka WordPress o nazwie Visual Form Builder w wersji poniżej 3.0.8 zawiera podatność umożliwiającą atakującemu nieuprawnione pobranie wpisów użytkowników w formularzach."
    + WORDPRESS_UPDATE_HINT,
    "WordPress Visual Form Builder plugin before 3.0.8 contains a information disclosure vulnerability. The plugin does not perform access control on entry form export, allowing an unauthenticated user to export the form entries as CSV files using the vfb-export endpoint.": "Wtyczka WordPress o nazwie Visual Form Builder w wersji poniżej 3.0.8 zawiera podatność umożliwiającą atakującemu nieuprawnione pobranie wpisów użytkowników w formularzach."
    + WORDPRESS_UPDATE_HINT,
    "Froxlor Server Management backup file was detected.": "Wykryto plik kopii zapasowej systemu Froxlor Server Management.",
    "WordPress WOOCS plugin before 1.3.7.5 is susceptible to cross-site scripting. The plugin does not sanitize and escape the woocs_in_order_currency parameter of the woocs_get_products_price_html AJAX action, available to both unauthenticated and authenticated users, before outputting it back in the response. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Wtyczka WordPress o nazwie WOOCS w wersji poniżej 1.3.7.5 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "PrestaShop modules by MyPrestaModules expose PHPInfo": "Wykryto moduł MyPrestaModules do systemu PrestaShop który udostępnia dane o konfiguracji serwera.",
    "A misconfig in Teslamate allows unauthorized access to /settings endpoint.": "Wykryto błędnie skonfigurowany system Teslamate, umożliwiający nieuprawniony dostęp do ustawień.",
    "In JetBrains TeamCity before 2023.11.4 path traversal allowing to perform limited admin actions was possible": "JetBrains TeamCity w wersji poniżej 2023.11.4 zawiera podatność Path Traversal, która w tym przypadku umożliwia nieuprawnione wykonanie części akcji administracyjnych."
    + UPDATE_HINT,
    "Log file was exposed.": "Wykryto plik logów. " + DATA_HIDE_HINT,
    "Revive Adserver 5.0.3 and prior contains a reflected cross-site scripting vulnerability in the publicly accessible afr.php delivery script. In older versions, it is possible to steal the session identifier and gain access to the admin interface. The query string sent to the www/delivery/afr.php script is printed back without proper escaping, allowing an attacker to execute arbitrary JavaScript code on the browser of the victim.": "Revive Adserver w wersji 5.0.3 i wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "All of the above Aapna WordPress theme through 1.3, Anand WordPress theme through 1.2, Anfaust WordPress theme through 1.1, Arendelle WordPress theme before 1.1.13, Atlast Business WordPress theme through 1.5.8.5, Bazaar Lite WordPress theme before 1.8.6, Brain Power WordPress theme through 1.2, BunnyPressLite WordPress theme before 2.1, Cafe Bistro WordPress theme before 1.1.4, College WordPress theme before 1.5.1, Connections Reloaded WordPress theme through 3.1, Counterpoint WordPress theme through 1.8.1, Digitally WordPress theme through 1.0.8, Directory WordPress theme before 3.0.2, Drop WordPress theme before 1.22, Everse WordPress theme before 1.2.4, Fashionable Store WordPress theme through 1.3.4, Fullbase WordPress theme before 1.2.1, Ilex WordPress theme before 1.4.2, Js O3 Lite WordPress theme through 1.5.8.2, Js Paper WordPress theme through 2.5.7, Kata WordPress theme before 1.2.9, Kata App WordPress theme through 1.0.5, Kata Business WordPress theme through 1.0.2, Looki Lite WordPress theme before 1.3.0, moseter WordPress theme through 1.3.1, Nokke WordPress theme before 1.2.4, Nothing Personal WordPress theme through 1.0.7, Offset Writing WordPress theme through 1.2, Opor Ayam WordPress theme through 18, Pinzolo WordPress theme before 1.2.10, Plato WordPress theme before 1.1.9, Polka Dots WordPress theme through 1.2, Purity Of Soul WordPress theme through 1.9, Restaurant PT WordPress theme before 1.1.3, Saul WordPress theme before 1.1.0, Sean Lite WordPress theme before 1.4.6, Tantyyellow WordPress theme through 1.0.0.5, TIJAJI WordPress theme through 1.43, Tiki Time WordPress theme through 1.3, Tuaug4 WordPress theme through 1.4, Tydskrif WordPress theme through 1.1.3, UltraLight WordPress theme through 1.2, Venice Lite WordPress theme before 1.5.5, Viala WordPress theme through 1.3.1, viburno WordPress theme before 1.3.2, Wedding Bride WordPress theme before 1.0.2, Wlow WordPress theme before 1.2.7 suffer from the same issue about the search box reflecting the results causing XSS which allows an unauthenticated attacker to exploit against users if they click a malicious link.": "Wykryto szablon WordPress:  Aapna w wersji nie większej niż 1.3, Anand w wersji nie większej niż 1.2, Anfaust w wersji nie większej niż 1.1, Arendelle w wersji poniżej 1.1.13, Atlast Business w wersji nie większej niż 1.5.8.5, Bazaar Lite w wersji poniżej 1.8.6, Brain Power w wersji nie większej niż 1.2, BunnyPressLite w wersji poniżej 2.1, Cafe Bistro w wersji poniżej 1.1.4, College w wersji poniżej 1.5.1, Connections Reloaded w wersji nie większej niż 3.1, Counterpoint w wersji nie większej niż 1.8.1, Digitally w wersji nie większej niż 1.0.8, Directory w wersji poniżej 3.0.2, Drop w wersji poniżej 1.22, Everse w wersji poniżej 1.2.4, Fashionable Store w wersji nie większej niż 1.3.4, Fullbase w wersji poniżej 1.2.1, Ilex w wersji poniżej 1.4.2, Js O3 Lite w wersji nie większej niż 1.5.8.2, Js Paper w wersji nie większej niż 2.5.7, Kata w wersji poniżej 1.2.9, Kata App w wersji nie większej niż 1.0.5, Kata Business w wersji nie większej niż 1.0.2, Looki Lite w wersji poniżej 1.3.0, moseter w wersji nie większej niż 1.3.1, Nokke w wersji poniżej 1.2.4, Nothing Personal w wersji nie większej niż 1.0.7, Offset Writing w wersji nie większej niż 1.2, Opor Ayam w wersji nie większej niż 18, Pinzolo w wersji poniżej 1.2.10, Plato w wersji poniżej 1.1.9, Polka Dots w wersji nie większej niż 1.2, Purity Of Soul w wersji nie większej niż 1.9, Restaurant PT w wersji poniżej 1.1.3, Saul w wersji poniżej 1.1.0, Sean Lite w wersji poniżej 1.4.6, Tantyyellow w wersji nie większej niż 1.0.0.5, TIJAJI w wersji nie większej niż 1.43, Tiki Time w wersji nie większej niż 1.3, Tuaug4 w wersji nie większej niż 1.4, Tydskrif w wersji nie większej niż 1.1.3, UltraLight w wersji nie większej niż 1.2, Venice Lite w wersji poniżej 1.5.5, Viala w wersji nie większej niż 1.3.1, viburno w wersji poniżej 1.3.2, Wedding Bride w wersji poniżej 1.0.2, Wlow w wersji poniżej 1.2.7 zawierający podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "The plugin does not ensure that users making. alive search are limited to published posts only, allowing unauthenticated users to make a crafted query disclosing private/draft/pending post titles along with their permalink": "Wtyczka WordPress o nazwie SearchWP Live Ajax Search w wersji poniżej 1.6.2 umożliwia odczyt niepublicznych postów."
    + WORDPRESS_UPDATE_HINT,
    "Github takeover was detected.": "Wykryto domenę kierującą do serwisu Github, ale strona docelowa nie istnieje. Atakujący może zarejestrować taką stronę i serwować tam swoje treści.",
    "Apache HTTP Server versions 2.4.0 through 2.4.39 are vulnerable to a limited cross-site scripting issue affecting the mod_proxy error page. An attacker could cause the link on the error page to be malformed and instead point to a page of their choice. This would only be exploitable where a server was set up with proxying enabled but was misconfigured in such a way that the Proxy Error page was displayed.": "Serwer Apache w wersji od 2.4.0 do 2.4.39 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.0 to 5.6.7, 5.4.0 to 5.4.12, 5.2 and below versions under SSL VPN web portal are vulnerable to cross-site scripting and allows attacker to execute unauthorized malicious script code via the error or message handling parameters.": "Fortinet FortiOS 6.0.0 do 6.0.4, 5.6.0 do 5.6.7, 5.4.0 do 5.4.12, oraz wersje 5.2 i wcześniejsze zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Jeesns 1.4.2 is vulnerable to reflected cross-site scripting that allows attackers to execute arbitrary web scripts or HTML via a crafted payload in the system error message's text field.": "System Jeesns w wersji 1.4.2 i potencjalniej wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Jeesns 1.4.2 is vulnerable to reflected cross-site scripting in the /newVersion component and allows attackers to execute arbitrary web scripts or HTML.": "System Jeesns w wersji 1.4.2 i potencjalnie wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Synacor Zimbra Collaboration Suite Collaboration before 8.8.11 is vulnerable to cross-site scripting via the AJAX and html web clients.": "Synacor Zimbra Collaboration Suite w wersji poniżej 8.8.11 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Multiple cross-site scripting (XSS) vulnerabilities in Open Bulletin Board (OpenBB) 1.0.6 and earlier allows remote attackers to inject arbitrary web script or HTML via the (1) redirect parameter to member.php, (2) to parameter to myhome.php (3) TID parameter to post.php, or (4) redirect parameter to index.php.": "Open Bulletin Board (OpenBB) w wersji 1.0.6 i wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Novius OS 5.0.1 (Elche) allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via a URL in the redirect parameter to admin/nos/login.": "Novius OS 5.0.1 (Elche) zawiera podatność Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie."
    + UPDATE_HINT,
    "GLPI prior 9.4.6 contains an open redirect vulnerability based on a regexp.": "GLPI w wersji wcześniejszej niż 9.4.6 zawiera podatność Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie."
    + UPDATE_HINT,
    "Planon before Live Build 41 is vulnerable to cross-site scripting.": "Oprogramowanie Planon w wersji poniżej Live Build 41 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "WordPress AcyMailing plugin before 7.5.0 contains an open redirect vulnerability due to improper sanitization of the redirect parameter. An attacker turning the request from POST to GET can craft a link containing a potentially malicious landing page and send it to the user.": "Wtyczka WordPress o nazwie AcyMailing w wersji mniejszej niż 7.5.0 zawiera podatność Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie."
    + WORDPRESS_UPDATE_HINT,
    "WordPress AnyComment plugin before 0.3.5 contains an open redirect vulnerability via an API endpoint which passes user input via the redirect parameter to the wp_redirect() function without being validated. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.": "Wtyczka WordPress o nazwie AnyComment w wersji poniżej 0.3.5 zawiera podatność Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie."
    + WORDPRESS_UPDATE_HINT,
    "Jenkins build-metrics 1.3 is vulnerable to a reflected cross-site scripting vulnerability that allows attackers to inject arbitrary HTML and JavaScript into the web pages the plugin provides.": "Moduł systemu Jenkins o nazwie build-metrics w wersji 1.3 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "WordPress Photo Gallery by 10Web plugin before 1.5.69 contains multiple reflected cross-site scripting vulnerabilities via the gallery_id, tag, album_id and theme_id GET parameters passed to the bwg_frontend_data AJAX action, available to both unauthenticated and authenticated users.": "Wtyczka WordPress o nazwie Photo Gallery by 10Web w wersji poniżej 1.5.69 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "A reflected cross-site scripting (XSS) vulnerability in the /public/launchNewWindow.jsp component of Zimbra Collaboration (aka ZCS) 9.0 allows unauthenticated attackers to execute arbitrary web script or HTML via request parameters.": "Komponent /public/launchNewWindow.jsp systemu Zimbra Collaboration w wersji 9.0 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Caddy 2.4.6 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site via a crafted URL and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.": "System Caddy w wersji 2.4.6 i potencjalnie wcześniejszych zawiera podatność Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie."
    + UPDATE_HINT,
    "Apache OFBiz 16.11.01 to 16.11.07 is vulnerable to cross-site scripting because data sent with contentId to /control/stream is not sanitized.": "Apache OFBiz w wersji 16.11.01 do 16.11.07 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Aruba Airwave before version 8.2.3.1 is vulnerable to reflected cross-site scripting.": "Aruba Ariwave w wersji poniżej 8.2.3.2 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "MindPalette NateMail 3.0.15 is susceptible to reflected cross-site scripting which could allows an attacker to execute remote JavaScript in a victim's browser via a specially crafted POST request. The application will reflect the recipient value if it is not in the NateMail recipient array. Note that this array is keyed via integers by default, so any string input will be invalid.": "MindPalette NateMail w wersji 3.0.15 i potencjalnie wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Jenkins Audit Trail 3.2 and earlier does not escape the error message for the URL Patterns field form validation, resulting in a reflected cross-site scripting vulnerability.": "Wtyczka Jenkins o nazwie Audit Trail w wersji 3.2 i wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "XWiki Platform is vulnerable to reflected XSS via the previewactions template. An attacker can inject JavaScript through the xcontinue parameter.": "Wykryto wersję platformy XWiki zawierającą podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "IceWarp WebMail 11.4.5.0 is vulnerable to cross-site scripting via the language parameter.": "IceWarp WebMail 11.4.5.0 (i potencjalnie wcześniejsze wersje) zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "KindEditor 4.1.11 contains a cross-site scripting vulnerability via the php/demo.php content1 parameter.": "KindEditor w wersji 4.1.11 i potencjalnie wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "twitter-server before 20.12.0 is vulnerable to cross-site scripting in some configurations. The vulnerability exists in the administration panel of twitter-server in the histograms component via server/handler/HistogramQueryHandler.scala.": "System twitter-server w wersji poniżej 20.12.0 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "WordPress FoodBakery before 2.2 contains an unauthenticated reflected cross-site scripting vulnerability. It does not properly sanitize the foodbakery_radius parameter before outputting it back in the response.": "Wtyczka WordPress o nazwie FoodBakery w wersji poniżej 2.2 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "EPrints 3.4.2 contains a reflected cross-site scripting vulnerability in the dataset parameter to the cgi/dataset_ dictionary URI.": "EPrints 3.4.2 (i potencjalnie wcześniejsze wersje) zawiera podatność  "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "Jenzabar 9.2.x through 9.2.2 contains a cross-site scripting vulnerability. It allows /ics?tool=search&query.": "Jenzabar w wersji 9.2.x do 9.2.2 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "In Cloudron 6.2, the returnTo parameter on the login page is vulnerable to cross-site scripting.": "Cloudron w wersji 6.2 i potencjalnie wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "A cross-site scripting vulnerability in application/controllers/dropbox.php in JustWriting 1.0.0 and below allow remote attackers to inject arbitrary web script or HTML via the challenge parameter.": "JustWriting w wersji 1.0.0 i wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "WordPress XML Sitemap Generator for Google plugin before 2.0.4 contains a cross-site scripting vulnerability that can lead to remote code execution. It does not validate a parameter which can be set to an arbitrary value, thus causing cross-site scripting via error message or remote code execution if allow_url_include is turned on.": "Wtyczka WordPress o nazwie XML Sitemap Generator for Google w wersji poniżej 2.0.4 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + " W niektórych konfiguracjach zawiera również podatność umożliwiającą zdalne wykonanie kodu. "
    + RCE_EFFECT_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "The Virtual Keyboard plugin for SquirrelMail 1.2.6/1.2.7 is prone to a cross-site scripting vulnerability because it fails to properly sanitize user-supplied input.": "Wtyczka systemu SquirrelMail o nazwie Virtual Keyboard w wersji 1.2.6/1.2.7 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Cross-site scripting vulnerability in Telerik.ReportViewer.WebForms.dll in Telerik Reporting for ASP.NET WebForms Report Viewer control before R1 2017 SP2 (11.0.17.406) allows remote attackers to inject arbitrary web script or HTML via the bgColor parameter to Telerik.ReportViewer.axd.": "Moduł Telerik.ReportViewer.WebForms.dll w narzędziu Telerik Reporting for ASP.NET WebForms Report Viewer control w wersji poniżej R1 2017 SP2 (11.0.17.406) zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Nginx is vulnerable to git configuration exposure.": "Wykryto błędną konfigurację serwera nginx umożliwiającą odczyt kodu źródłowego aplikacji.",
    "Ruby on Rails 6.0.0-6.0.3.1 contains a CRLF issue which allows JavaScript to be injected into the response, resulting in cross-site scripting.": "Ruby on Rails 6.0.0-6.0.3.1 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "The Email Subscribers by Icegram Express - Email Marketing, Newsletters, Automation for WordPress & WooCommerce plugin for WordPress is vulnerable to SQL Injection via the 'run' function of the 'IG_ES_Subscribers_Query' class in all versions up to, and including, 5.7.14 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.": "Wtyczka WordPress o nazwie Email Subscribers by Icegram Express - Email Marketing, Newsletters, Automation for WordPress & WooCommerce w wersji do 5.7.14 włącznie zawiera podatność SQL injection, umożliwiającą atakującemu odczyt dowolnych danych z bazy danych."
    + WORDPRESS_UPDATE_HINT,
    "Hotel Druid 3.0.2 contains a cross-site scripting vulnerability in multiple pages which allows for arbitrary execution of JavaScript commands.": "Hotel Druid w wersji 3.0.2 i potencjalnie wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    'Cacti contains a cross-site scripting vulnerability via "http://<CACTI_SERVER>/auth_changepassword.php?ref=<script>alert(1)</script>" which can successfully execute the JavaScript payload present in the "ref" URL parameter.': "Wykryto, że system Cacti zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "WordPress Supsystic Ultimate Maps plugin before 1.2.5 contains an unauthenticated reflected cross-site scripting vulnerability due to improper sanitization of the tab parameter on the options page before outputting it in an attribute.": "Wtyczka WordPress o nazwie Supsystic Ultimate Maps w wersji poniżej 1.2.5 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "WordPress Supsystic Contact Form plugin before 1.7.15 contains a cross-site scripting vulnerability. It does not sanitize the tab parameter of its options page before outputting it in an attribute.": "Wtyczka WordPress o nazwie  Supsystic Contact Form w wersji poniżej 1.7.15 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "Django 1.11.x before 1.11.15 and 2.0.x before 2.0.8 contains an open redirect vulnerability. If  django.middleware.common.CommonMiddleware and APPEND_SLASH settings are selected, and if the project has a URL pattern that accepts any path ending in a slash, an attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.": "Wykryto framework Django w wersji 1.11.x poniżej 1.11.15 lub 2.0.x poniżej 2.0.8 w konfiguracji zawierającej podatność Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie."
    + UPDATE_HINT,
    "A SQL injection vulnerability in the product_all_one_img and image_product parameters of the ApolloTheme AP PageBuilder component through 2.4.4 for PrestaShop allows unauthenticated attackers to exfiltrate database data.": "Komponent ApolloTheme AP PageBuilder systemu PrestaShop w wersji do 2.4.4 włącznie zawiera podatność SQL Injection, umożliwiającą atakującemu pobranie całej zawartości bazy danych. "
    + UPDATE_HINT,
    "Mara CMS 7.5 allows reflected cross-site scripting in contact.php via the theme or pagetheme parameters.": "Mara CMS w wersji 7.5 (i potencjalnie wcześniejszych) zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "NeDi 1.9C is vulnerable to cross-site scripting because of an incorrect implementation of sanitize() in inc/libmisc.php. This function attempts to escape the SCRIPT tag from user-controllable values, but can be easily bypassed, as demonstrated by an onerror attribute of an IMG element as a Devices-Config.php?sta= value.": "NeDi w wersji 1.9C i potencjalnie wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "KMCIS CaseAware contains a reflected cross-site scripting vulnerability via the user parameter transmitted in the login.php query string.": "Wykryto, że KMCIS CaseAware zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Edito CMS is a website content management framework. Some old versions allowed for configuration files downloads, which could lead to confidential data (e.g. database credentials) exposure.": "Wykryto system Edito CMS w wersji umożliwiającej nieuprawnione pobranie plików konfiguracyjnych, zawierających potencjalnie dane dostępowe do bazy danych."
    + UPDATE_HINT,
    "Kodi 17.1 is vulnerable to local file inclusion vulnerabilities because of insufficient validation of user input.": "Narzędzie Kodi w wersji 17.1 zawiera podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików z serwera."
    + UPDATE_HINT,
    'Tiki Wiki CMS Groupware 7.0 is vulnerable to cross-site scripting via the GET "ajax" parameter to snarf_ajax.php.': "Tiki Wiki CMS Groupware w wersji 7.0 (i potencjalnie wcześniejszych) zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "WordPress Plugin WPML Version < 4.6.1  is vulnerable to RXSS via wp_lang parameter.": "Wtyczka WordPress o nazwie WPML w wersji poniżej 4.6.1 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Docker Registry Listing enabled.": "Wykryto publicznie dostępny listing kontenerów w systemie Docker Registry."
    + DATA_HIDE_HINT,
    "Multiple cross-site scripting (XSS) vulnerabilities in SquirrelMail 1.4.2 allow remote attackers to execute arbitrary script and possibly steal authentication information via multiple attack vectors, including the mailbox parameter in compose.php.": "System SquirrelMail w wersji 1.4.2 i potencjalnie wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    'Multiple directory traversal vulnerabilities in the web server for Motorola SURFBoard cable modem SBV6120E running firmware SBV6X2X-1.0.0.5-SCM-02-SHPC allow remote attackers to read arbitrary files via (1) "//" (multiple leading slash), (2) ../ (dot dot) sequences, and encoded dot dot sequences in a URL request.': "Modem SBV6120E z firmware SBV6X2X-1.0.0.5-SCM-02-SHPC zawiera podatność Directory Traversal, umożliwiającą atakującemu odczyt dowolnych plików.",
    "Parallels H-Sphere 3.0.0 P9 and 3.1 P1 contains multiple cross-site scripting vulnerabilities in login.php in webshell4. An attacker can inject arbitrary web script or HTML via the err, errorcode, and login parameters, thus allowing theft of cookie-based authentication credentials and launch of other attacks.": "Parallels H-Sphere 3.0.0 P9 i 3.1 P1 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Apereo CAS through 6.4.1 allows cross-site scripting via POST requests sent to the REST API endpoints.": "Apereo CAS w wersji do 6.4.1 włącznie zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "The Quttera Web Malware Scanner WordPress plugin before 3.4.2.1 doesn't restrict access to detailed scan logs, which allows a malicious actor to discover local paths and portions of the site's code": "Wtyczka WordPress o nazwie Quttera Web Malware Scanner w wersji poniżej 3.4.2.1 umożliwia atakującemu pobranie dziennika skanowania i poznanie ścieżek i fragmentów kodu aplikacji."
    + WORDPRESS_UPDATE_HINT,
    "Odoo is a business suite that has features for many business-critical areas, such as e-commerce, billing, or CRM. Versions before the 16.0 release are vulnerable to CVE-2023-1434 and is caused by an incorrect content type being set on an API endpoint.": "System Odoo w wersji poniżej 16.0 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "http/cves/2023/CVE-2023-6875.yaml": "Wtyczka WordPress o nazwie The POST SMTP Mailer - Email log, Delivery Failure Notifications and Best Mail SMTP for WordPress w wersji do 2.8.7 włącznie zawiera podatność umożliwiającą nieuprawniony dostęp i modyfikację danych."
    + UPDATE_HINT,
    "phpinfo() is susceptible to resource exposure in unprotected composer vendor folders via phpfastcache/phpfastcache.": "Wykryto błędną konfigurację narzędzia phpfastcache zawierającą publicznie dostępny plik phpinfo, udostępniający informacje o konfiguracji serwera. "
    + DATA_HIDE_HINT,
    "GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka ShellShock.": "Wykryto powłokę Bash w wersji do 4.3 zawierającą podatność ShellShock, umożliwiającą atakującemu zdalne wykonanie kodu. "
    + UPDATE_HINT,
    "WordPress White Label CMS plugin before 2.2.9 contains a reflected cross-site scripting vulnerability. It does not sanitize and validate the wlcms[_login_custom_js] parameter before outputting it back in the response while previewing.": "Wtyczka WordPress o nazwie White Label CMS w wersji poniżej 2.2.9 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "The W3 Total Cache WordPress plugin was affected by an Unauthenticated Server Side Request Forgery (SSRF) security vulnerability.": "Wykryto wtyczkę WordPress o nazwie W3 Total Cache w wersji zawierającej podatność Server Side Request Forgery (SSRF), czyli umożliwiającą atakującemu dostęp do zasobów w sieci lokalnej. "
    + WORDPRESS_UPDATE_HINT,
    "Knowage Suite 7.3 contains an unauthenticated reflected cross-site scripting vulnerability. An attacker can inject arbitrary web script in '/servlet/AdapterHTTP' via the 'targetService' parameter.": "Knowage Suite w wersji 7.3 i potencjalnie wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Moodle contains a cross-site scripting vulnerability via the Jsmol plugin and may also be susceptible to local file inclusion or server-side-request forgery. An attacker can execute arbitrary script in the browser of an unsuspecting user and steal cookie-based authentication credentials and launch other attacks.": "Wykryto system Moodle zawierający we wtyczce Jsmol podatność "
    + REFLECTED_XSS_DESCRIPTION
    + " (i potencjalnie inne podatności). "
    + UPDATE_HINT,
    "ClinicCases 7.3.3 is susceptible to multiple reflected cross-site scripting vulnerabilities that could allow unauthenticated attackers to introduce arbitrary JavaScript by crafting a malicious URL. This can result in account takeover via session token theft.": "ClinicCases w wersji 7.3.3 i potencjalnie wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "SquirrelMail Address Add 1.4.2 plugin contains a cross-site scripting vulnerability. It fails to properly sanitize user-supplied input, thus allowing an attacker to execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Wtyczka SquirrelMail o nazwie Address Add w wersji 1.4.2 i potencjalnie wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "PacsOne Server (PACS Server In One Box) below 7.1.1 is vulnerable to cross-site scripting.": "PacsOne Server (PACS Server In One Box) w wersji poniżej 7.1.1 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "The Web Application Firewall in Bitrix24 up to and including 20.0.0 allows XSS via the items[ITEMS][ID] parameter to the components/bitrix/mobileapp.list/ajax.php/ URI.": "Komponent Web Application Firewall w Bitrix24 w wersji do 20.0.0 włącznie zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "SysAid 20.3.64 b14 contains a cross-site scripting vulnerability via the /KeepAlive.jsp?stamp= URI.": "SysAid w wersji 20.3.64 b14 i potencjalnie wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "A reflected XSS issue was identified in the LTI module of Moodle. The vulnerability exists due to insufficient sanitization of user-supplied data in the LTI module. A remote attacker can trick the victim to follow a specially crafted link and execute arbitrary HTML and script code in user's browser in context of vulnerable website to steal potentially sensitive information, change appearance of the web page, can perform phishing and drive-by-download attacks.": "Wykryto, że moduł LTI systemu Moodle zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Path Equivalence – ‘file.Name’ (Internal Dot) vulnerability in Apache Tomcat which may lead to Remote Code Execution, information disclosure, or malicious content injection via writable session files.": "Wykryto serwer Apache Tomcat zawierający podatność CVE-2025-24813 umożliwiającą atakującemu zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Detects potential 403 Forbidden bypass vulnerabilities by using nullbyte.": "Wykryto, że umieszczenie w adresie bajtu o kodzie zerowym umożliwia ominięcie kontroli dostępu do strony (statusu 403 Forbidden).",
    "Detects potential 403 Forbidden bypass vulnerabilities by using nonexistent HTTP methods.": "Wykryto, że za pomocą podania niestandardowej metody HTTP można ominąć kontrolę dostępu do strony (status 403 Forbidden).",
    "Detects potential 403 Forbidden bypass vulnerabilities by adding headers (e.g., X-Forwarded-For, X-Original-URL).": "Wykryto, że za pomocą podania dodatkowych nagłówków HTTP, takich jak np. X-Forwarded-For lub X-Original-URL, można ominąć kontrolę dostępu do strony (status 403 Forbidden).",
    "Redis service was accessed with easily guessed credentials.": "Wykryto system Redis, do którego udało się zalogować po zgadnięciu hasła. Oznacza to, że atakujący może uzyskać dostęp do danych w systemie i je modyfikować lub usunąć.",
    "NETGEAR routers R6250 before 1.0.4.6.Beta, R6400 before 1.0.1.18.Beta, R6700 before 1.0.1.14.Beta, R6900, R7000 before 1.0.7.6.Beta, R7100LG before 1.0.0.28.Beta, R7300DST before 1.0.0.46.Beta, R7900 before 1.0.1.8.Beta, R8000 before 1.0.3.26.Beta, D6220, D6400, D7000, and possibly others allow remote attackers to execute arbitrary commands via shell metacharacters in the path info to cgi-bin/.": "Routery NETGEAR R6250 w wersji poniżej 1.0.4.6.Beta, R6400 w wersji poniżej 1.0.1.18.Beta, R6700 w wersji poniżej 1.0.1.14.Beta, R6900, R7000 w wersji poniżej 1.0.7.6.Beta, R7100LG w wersji poniżej 1.0.0.28.Beta, R7300DST w wersji poniżej 1.0.0.46.Beta, R7900 w wersji poniżej 1.0.1.8.Beta, R8000 w wersji poniżej 1.0.3.26.Beta, D6220, D6400, D7000 i potencjalnie inne zawierają podatność umożliwiającą atakującemu zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION,
    "SuiteCRM is an open-source Customer Relationship Management (CRM) software application. Prior to versions 7.14.4 and 8.6.1, a vulnerability in events response entry point allows for a SQL injection attack. Versions 7.14.4 and 8.6.1 contain a fix for this issue.": "SuiteCRM to otwartoźródłowy system Customer Relationship Management (CRM). W wersji poniżej 7.14.4 (a w gałęzi 8 - 8.6.1) zawiera podatność SQL Injection, umożliwiającą atakującemu pobranie danych z bazy danych.",
    "Oracle E-Business Suite 12.2.3 through 12.2.11 is susceptible to remote code execution via the Oracle Web Applications Desktop Integrator product, Upload component. An attacker with HTTP network access can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.": "Oracle E-Business Suite w wersji od 12.2.3 do 12.2.11 zawiera podatność umożliwiającą atakującemu zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "An exposed Android debug bridge was discovered.": "Wykryto publicznie dostępny interfejs Android Debug Bridge. Rekomendujemy, aby takie interfejsy nie były dostępne publicznie.",
    "http/cves/2020/CVE-2020-9376.yaml": "Wykryto niewspieranie urządzenie D-Link DIR-610 zawierające podatność CVE-2020-9376, umożliwiającą atakującemu nieuprawnione pobieranie wrażliwych informacji i potencjalnie nieuprawniony dostęp.",
    "VSFTPD 2.3.4 contains a backdoor command execution vulnerability.": "VSFTPD w wersji 2.3.4 zawiera szkodliwy kod umożliwiający nieuprawniony dostęp do systemu."
    + UPDATE_HINT,
    "Grafana default admin login credentials were detected.": "Wykryto system Grafana, do którego można zalogować się domyślnymi poświadczeniami.",
    "An issue in issabel-pbx v.4.0.0-6 allows a remote attacker to obtain sensitive information via the modules directory": "Narzędzie issabel-pbx w wersji v.4.0.0-6 i potencjalnie wcześniejszych zawiera podatność umożliwiającą atakującemu nieuprawniony dostęp do wrażliwych informacji."
    + UPDATE_HINT,
    "File read and file write to RCE by deploying a vhost with MBeanFactory/createStandardHost and DiagnosticCommand/jfrStart": "Wykryto system Jolokia zawierający podatność umożliwiającą zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "An improper authorization check was identified within ProjectSend version r1605 that allows an attacker to perform sensitive actions such as enabling user registration and auto validation, or adding new entries in the whitelist of allowed extensions for uploaded files. Ultimately, this allows to execute arbitrary PHP code on the server hosting the application.": "ProjectSend w wersji r1605 i potencjalnie wcześniejszych umożliwia atakującemu nieuprawnione wykonywanie działań takich jak rejestracja czy zmiana konfiguracji, co w konsekwencji prowadzi do zdalnego wykonania kodu.",
    "WordPress WP Courses Plugin < 2.0.29 contains a critical information disclosure which exposes private course videos and materials.": "Wtyczka WordPress o nazwie WP Courses w wersji poniżej 2.0.29 zawiera podatność umożliwiającą dostęp do prywatnych materiałów kursowych.",
    "PHP CGI - Argument Injection (CVE-2024-4577) is a critical argument injection flaw in PHP.": "Wykryto PHP CGI zawierające podatność CVE-2024-4577 umożliwiającą atakującemu zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION,
    "Confluence is susceptible to the Installation page exposure due to misconfiguration.": "Wykryto system Confluence udostępniający instalator. Ta konfiguracja umożliwia atakującemu zmianę ustawień i potencjalnie nieuprawniony dostęp do systemu.",
    "Jenkins Dashboard is exposed to external users.": "Panel systemu Jenkins jest dostępny publicznie.",
    "This template checks for unauthenticated command execution vulnerability in Netgear DGN devices. Attackers can bypass authentication mechanisms and execute arbitrary commands with root privileges.": "Wykryto urządzenie Netgear DGN umożliwiające atakującemu wykonywanie bez uwierzytelnienia dowolnych poleceń z uprawnieniami administratora."
    + RCE_EFFECT_DESCRIPTION,
    "Artifactory anonymous repo is exposed.": "Wykryto anonimowe repozytorium systemu Artifactory.",
    "The MKdocs 1.2.2 built-in dev-server allows directory traversal using the port 8000, enabling remote exploitation to obtain sensitive information. Note the vendor has disputed the vulnerability (see references) because the dev server must be used in an unsafe way (namely public) to have this vulnerability exploited.": "Wykryto serwer deweloperski systemu MKdocs w wersji 1.2.2 zawierający podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików z dysku.",
    "eQ-3 AG Homematic CCU3 3.43.15 and earlier allows remote attackers to read arbitrary files of the device's filesystem, aka local file inclusion. This vulnerability can be exploited by unauthenticated attackers with access to the web interface.": "Sterownik eQ-3 AG Homematic CCU w wersji 3.43.15 i wcześniejszych zawiera podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików z dysku.",
    "Zeit Next.js before 4.2.3 is susceptible to local file inclusion under the /_next request namespace. An attacker can obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.": "Zeit Next.js w wersji poniżej 4.2.3 zawiera podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików z dysku."
    + UPDATE_HINT,
    "Dump password hashes in use within a PostgreSQL database.": "Wykryto, że po zalogowaniu do bazy danych jest możliwość pobrania nazw użytkowników bazy danych i haszy ich haseł.",
    "List users from Postgresql Database.": "Wykryto, że po zalogowaniu do bazy danych jest możliwość pobrania nazw użytkowników bazy danych.",
    "javascript/enumeration/pgsql/pgsql-list-database.yaml": "Wykryto, że po zalogowaniu do bazy danych jest możliwość pobrania nazw baz danych.",
    "Redwood Report2Web 4.3.4.5 and 4.5.3 contains a cross-site scripting vulnerability in the login panel which allows remote attackers to inject JavaScript via the signIn.do urll parameter.": "Redwood Report2Web 4.3.4.5 i 4.5.3 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Galera WebTemplate 1.0 is affected by a directory traversal vulnerability that could reveal information from /etc/passwd and /etc/shadow.": "Galera WebTemplate 1.0 zawiera podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików z dysku.",
    "Selea Targa IP OCR-ANPR camera suffers from an unauthenticated local file inclusion vulnerability because input passed through the Download Archive in Storage page using get_file.php script is not properly verified before being used to download files. This can be exploited to disclose the contents of arbitrary and sensitive files via directory traversal attacks and aid the attacker in disclosing clear-text credentials.": "Wykryto, że kamera Selea Targa IP OCR-ANPR zawiera podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików z dysku, w tym zawierających dane uwierzytelniające.",
    "Allied Telesis AT-GS950/8 until Firmware AT-S107 V.1.1.3 is susceptible to local file inclusion via its web interface.": "Allied Telesis AT-GS950/8 w wersji do AT-S107 V.1.1.3 zawiera podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików z dysku."
    + UPDATE_HINT,
    "The detected website is defaced.": "Wykryto, że strona internetowa została zaatakowana i zmieniono wyświetlaną na niej treść.",
    "Pulse Secure Pulse Connect Secure (PCS) 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4 all contain an arbitrary file reading vulnerability that could allow unauthenticated remote attackers to send a specially crafted URI to gain improper access.": "Pulse Secure Pulse Connect Secure (PCS) w wersji 8.2 poniżej 8.2R12.1, 8.3 poniżej 8.3R7.1 i 9.0 poniżej 9.0R3.4 zawiera podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. Ta podatność może również umożliwić atakującemu dostęp do systemu."
    + UPDATE_HINT,
    "Session Validation attacks in Apache Superset versions up to and including 2.0.1. Installations that have not altered the default configured SECRET_KEY according to installation instructions allow for an attacker to authenticate and access unauthorized resources. This does not affect Superset administrators who have changed the default value for SECRET_KEY config.": "Wykryto system Apache Superset w wersji do 2.0.1 z domyślną wartością zmiennej SECRET_KEY, co umożliwia atakującemu nieuprawniony dostęp do systemu.",
    "Postgresql has a flaw that allows the attacker to login with empty password.": "Wykryto bazę danych PostgreSQL do której można zalogować się pustym hasłem.",
    "Postgres service was accessed with easily guessed credentials.": "Wykryto bazę danych PostgreSQL do której można zalogować się prostym loginem/hasłem.",
    "custom:CVE-2025-24016": "Wykryto serwer Wazuh zawierający podatność CVE-2025-24016 umożliwiającą atakującemu zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    'This template detects an unsafe deserialization vulnerability in Wazuh servers.\nThe DistributedAPI deserializes JSON data using as_wazuh_object. If an attacker injects\na malicious object (via __unhandled_exc__), arbitrary Python code execution can be achieved.\nInstead of triggering a shutdown (e.g. via exit), this template uses a non-existent class \n("NotARealClass") to generate a NameError. A NameError in the response indicates that the \npayload reached the vulnerable deserialization function.': "Wykryto serwer Wazuh zawierający podatność CVE-2025-24016 umożliwiającą atakującemu zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Tomcat's credential disclosure leading to Remote Code Execution via WAR upload.": "Wykryto, że dane dostępowe systemu Tomcat są publicznie dostępne, co umożliwia upload pliku WAR a w konsekwencji zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION,
    "When running Apache Tomcat versions 9.0.0.M1 to 9.0.0, 8.5.0 to 8.5.22, 8.0.0.RC1 to 8.0.46 and 7.0.0 to 7.0.81 with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default servlet to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.": "Serwer Apache Tomcat w wersji od 9.0.0.M1 do 9.0.0, 8.5.0 do 8.5.22, 8.0.0.RC1 do 8.0.46 i 7.0.0 do 7.0.81 z włączoną metodą HTTP PUT umożliwia upload pliku JSP a w konsekwencji zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "The YARPP Yet Another Related Posts Plugin plugin for WordPress is vulnerable to unauthorized access due to a missing capability check in the ~/includes/yarpp_pro_set_display_types.php file in all versions up to, and including, 5.30.10. This makes it possible for unauthenticated attackers to set display types.": "Wtyczka WordPress o nazwie YARPP Yet Another Related Posts Plugin w wersji do 5.30.10 włącznie umożliwia atakującemu zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "RCE in Jolokia < 1.7.1 using AccesLogValve": "Narzędzie Jolokia w wersji poniżej 1.7.1 zawiera podatność umożliwiającą zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "The WordPress File Upload plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 4.24.11 via wfu_file_downloader.php. This makes it possible for unauthenticated attackers to read or delete files outside of the originally intended directory. Successful exploitation requires the targeted WordPress installation to be using PHP 7.4 or earlier.": "Wtyczka WordPress o nazwie File Upload w wersji do 4.24.11 włącznie zawiera podatność umożliwiającą atakującemu w niektórych sytuacjach odczyt i usuwanie dowolnych plików z serwera."
    + WORDPRESS_UPDATE_HINT,
    'A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root. If files outside of the document root are not protected by "require all denied" these requests can succeed. Additionally, this flaw could leak the source of interpreted files like CGI scripts. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions.': "Serwer Apache w wersji 2.4.49  (ale nie wcześniejszych) umożliwia w niektórych sytuacjach odczyt plików z dysku."
    + UPDATE_HINT,
    "Apache Struts 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 is susceptible to remote command injection attacks. The Jakarta Multipart parser has incorrect exception handling and error-message generation during file upload attempts, which can allow an attacker to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header. This was exploited in March 2017 with a Content-Type header containing a #cmd= string.": "Apache Struts 2.3.x w wersji poniżej 2.3.32 i 2.5.x w wersji poniżej 2.5.10.1 zawiera podatność umożliwiającą zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Apache Struts2 S2-062 is vulnerable to remote code execution. The fix issued for CVE-2020-17530 (S2-061) was incomplete, meaning some of the tag's attributes could still perform a double evaluation if a developer applied forced OGNL evaluation by using the %{...} syntax.": "Apache Struts2 w wersji S2-062 zawiera podatność umożliwiającą zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "The WP Umbrella: Update Backup Restore & Monitoring plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 2.17.0 via the 'filename' parameter of the 'umbrella-restore' action. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.": "Wtyczka WordPress o nazwie WP Umbrella: Update Backup Restore & Monitoring w wersji do 2.17.0 włącznie zawiera podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików na serwerze, a w niektórych sytuacjach zdalne wykonanie kodu."
    + WORDPRESS_UPDATE_HINT,
    "http/cves/2024/CVE-2024-10400.yaml": "Wtyczka WordPress o nazwie Tutor LMS w wersji do 2.7.6 włącznie zawiera podatnosć SQL Injection umożliwiającą atakującemu pobranie całej zawartości bazy danych."
    + WORDPRESS_UPDATE_HINT,
    "Confluence Server and Data Center is susceptible to an unauthenticated remote code execution vulnerability.": "Wykryto system Confluence Server and Data Center w wersji, która umożliwia atakującemu zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Atlassian Confluence Server allows remote attackers to view restricted resources via local file inclusion in the /s/ endpoint.": "Wykryto system Atlassian Confluence Server w wersji umożliwiającej atakującym nieuprawniony dostęp do zasobów."
    + UPDATE_HINT,
    "Attempts to show all variables on a MySQL server.": "Wykryto, że serwer MySQL umożliwia logowanie prostym hasłem.",
    "Enrollment System Project V1.0, developed by Sourcecodester, has been found to be vulnerable to SQL Injection (SQLI) attacks. This vulnerability allows an attacker to manipulate the SQL queries executed by the application. The system fails to properly validate user-supplied input in the username and password fields during the login process, enabling an attacker to inject malicious SQL code. By exploiting this vulnerability, an attacker can bypass authentication and gain unauthorized access to the system.": "Enrollment System Project V1.0 zawiera podatność SQL Injection umożliwiającą atakującemu nieuprawniony dostęp do systemu.",
    "Checks for MySQL servers with an empty password for root or anonymous.": "Wykryto serwer MySQL do którego można zalogować się pustym hasłem.",
    "WordPress WooCommerce plugin before 3.1.2 does not have authorisation and CSRF checks in the wpt_admin_update_notice_option AJAX action (available to both unauthenticated and authenticated users), as well as does not validate the callback parameter, allowing unauthenticated attackers to call arbitrary functions with either none or one user controlled argument.": "Wtyczka WordPress o nazwie WooCommerce w wersji poniżej 3.1.2 umożliwia atakującemu nieuprawnione uruchamianie niektórych funkcji w systemie."
    + WORDPRESS_UPDATE_HINT,
    "Primetek Primefaces 5.x is vulnerable to a weak encryption flaw resulting in remote code execution.": "Primetek Primefaces 5.x zawiera podatność umożliwiającą zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Detects exposed internal PKI infrastructure including CRL distribution points and OCSP responders": "Wykryto publicznie dostępną infrastrukturę PKI. Rekomendujemy, aby takie zasoby nie były dostępne publicznie.",
    "After the initial setup process, some steps of setup.php file are reachable not only by super-administrators but also by unauthenticated users. A malicious actor can pass step checks and potentially change the configuration of Zabbix Frontend.": "Wykryto, że niektóre kroki instalacji systemu Zabbix Frontend są dostępne nie tylko dla administratorów, ale też dla nieuprawnionych użytkowników, co umożliwia atakującemu zmianę konfiguracji systemu. Rekomendujemy, aby takie zasoby nie były dostępne publicznie.",
    "A vulnerability in NuPoint Messenger (NPM) of Mitel MiCollab through 9.8.0.33 allows an unauthenticated attacker to conduct a SQL injection attack due to insufficient sanitization of user input. A successful exploit could allow an attacker to access sensitive information and execute arbitrary database and management operations.": "NuPoint Messenger w wersji do 9.8.0.33 włącznie zawiera podatność SQL Injection, umożliwiającą atakującemu pobranie całej zawartości bazy danych."
    + UPDATE_HINT,
    "Files on the host computer can be accessed from the Gradio interface": "Interfejs Gradio umożliwia dostęp do plików na komputerze.",
    "gSOAP 2.8 is vulnerable to local file inclusion.": "gSOAP w wersji 2.8 i potencjalnie wcześniejszych zawiera podatność Local File Inclusion umożliwiającą atakującemu odczyt niektórych plików z dysku."
    + UPDATE_HINT,
    "Rubedo CMS through 3.4.0 contains a directory traversal vulnerability in the theme component, allowing unauthenticated attackers to read and execute arbitrary files outside of the service root path, as demonstrated by a /theme/default/img/%2e%2e/..//etc/passwd URI.": "Rubedo CMS w wersji do 3.4.0 włącznie zawiera podatność Local File Inclusion umożliwiającą atakującemu odczyt plików z dysku."
    + UPDATE_HINT,
    # The translation is different from the original message as the template doesn't check that it's **not* possible to access the debug env **without** injecting stuff.
    "Symfony, a popular PHP framework, offers a module called symfony/runtime that allows developers to decouple their PHP applications from the global state. This module enhances the flexibility and maintainability of Symfony-based applications. However, a security vulnerability was discovered in symfony/runtime versions prior to 5.4.46, 6.4.14, and 7.1.7. When the `register_argv_argc` PHP directive is set to `on`, users could manipulate the environment or debug mode used by the kernel when handling requests by crafting a specific query string in the URL. This vulnerability could potentially allow attackers to alter the application's behavior or gain unauthorized access to sensitive information. To address this issue, the Symfony team released patches in versions 5.4.46, 6.4.14, and 7.1.7 of the symfony/runtime module. In these updated versions, the `SymfonyRuntime` class has been modified to ignore the `argv` values for non-SAPI PHP runtimes. This change prevents the manipulation of the kernel's environment or debug mode through the query string, thereby mitigating the security risk. It is highly recommended that developers using Symfony/runtime update their applications to the latest patched versions to ensure the security and integrity of their Symfony-based projects. By applying these updates, developers can protect their applications from potential exploits and maintain a secure environment for their users.": "Wykryto, że po podaniu odpowiednich parametrów w ścieżce jest możliwość uzyskania dostępu do trybu debug frameworku Symfony, w tym potencjalnie do wrażliwych informacji konfiguracyjnych. Może to wynikać z podatności CVE-2024-50340 (występującej w wersji Symfony mniejszej od 5.4.46, w gałęzi 6 - mniejszej niż 6.4.14, a w gałęzi 7 - mniejszej niż 7.1.7) lub z konfiguracji, że tryb debug jest publicznie dostępny.",
    "symfony/runtime is a module for the Symphony PHP framework which enables decoupling PHP applications from global state. When the `register_argv_argc` php directive is set to `on` , and users call any URL with a special crafted query string, they are able to change the environment or debug mode used by the kernel when handling the request. As of versions 5.4.46, 6.4.14, and 7.1.7 the `SymfonyRuntime` now ignores the `argv` values for non-SAPI PHP runtimes.": "Wykryto, że po podaniu odpowiednich parametrów w ścieżce jest możliwość uzyskania dostępu do trybu debug frameworku Symfony, w tym potencjalnie do wrażliwych informacji konfiguracyjnych. Może to wynikać z podatności CVE-2024-50340 (występującej w wersji Symfony mniejszej od 5.4.46, w gałęzi 6 - mniejszej niż 6.4.14, a w gałęzi 7 - mniejszej niż 7.1.7) lub z konfiguracji, że tryb debug jest publicznie dostępny.",
    "Affected versions of Atlassian Jira Limited Server and Data Center are vulnerable to local file inclusion because they allow remote attackers to read particular files via a path traversal vulnerability in the /WEB-INF/web.xml endpoint.": "Wykryto system Atlassian Jira Limited Server and Data Center zawierający podatność Local File Inclusion umożliwiającą atakującemu odczyt niektórych plików z dysku."
    + UPDATE_HINT,
    "The Redis server running on the remote host is not protected by password authentication. A remote attacker can exploit this to gain unauthorized access to the server.": "Wykryto serwer Redis dostępny bez uwierzytelniania. Rekomendujemy, aby nie był dostępny publicznie.",
    "http/misconfiguration/springboot/springboot-httptrace.yaml": "Wykryto informację na temat żądań i odpowiedzi HTTP przetwarzanych przez system Spring Boot.",
    "Multiple fuzzes for /etc/passwd on passed URLs were conducted, leading to multiple instances of local file inclusion vulnerability.": "Wykryto podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnego pliku z dysku.",
    "WordPress LearnPress plugin before 4.1.6 contains a cross-site scripting vulnerability. It does not sanitize and escape the lp-dismiss-notice before outputting it back via the lp_background_single_email AJAX action.": "Wtyczka WordPress o nazwie LearnPress w wersji poniżej 4.1.6 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "An Open Redirect vulnerability in Odoo versions <= 8.0-20160726 and 9.0. This issue allows an attacker to redirect users to untrusted sites via a crafted URL.": "System Odoo w wersji do 8.0-20160726 włącznie i w wersji 9.0 zawiera podatność Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie."
    + UPDATE_HINT,
    "phpPgAdmin 4.2.1 is vulnerable to local file inclusion in libraries/lib.inc.php when register globals is enabled. Remote attackers can read arbitrary files via a .. (dot dot) in the _language parameter to index.php.": "phpPgAdmin w wersji 4.2.1 zawiera podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku."
    + UPDATE_HINT,
    "Hoteldruid v3.0.5 was discovered to contain a SQL injection vulnerability via the n_utente_agg parameter at /hoteldruid/interconnessioni.php.": "Hoteldruid w wersji 3.0.5 i potencjalnie wcześniejszych zawiera podatność SQL Injection, umożliwiającą atakującemu pobranie pełnej zawartości bazy danych.",
    "Keycloak 8.0 and prior contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.": "Keycloak w wersji 8.0 i wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Unauthenticated Reflected Cross-Site Scripting (XSS) vulnerability in ThemePunch OHG Essential Grid plugin <= 3.1.0 versions.": "Wtyczka WordPress o nazwie ThemePunch OHG Essential Grid w wersji do 3.1.0 włącznie zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "[no description] http/exposures/logs/action-controller-exception.yaml": "Wykryto dziennik zdarzeń Action Controller.",
    "Detection of SAP NetWeaver ABAP Webserver /public/info page": "Wykryto stronę z informacjami systemu SAP NetWeaver ABAP Webserver.",
    "An integer overflow in process_bin_sasl_auth function in Memcached, which is responsible for authentication commands of Memcached binary protocol, can be abused to cause heap overflow and lead to remote code execution.": "Memcached w wersji 1.4.31 i wcześniejszych zawiera podatność umożliwiającą potencjalnie atakującemu zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "The Backup Migration plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 1.3.7 via the /includes/backup-heart.php file. This is due to an attacker being able to control the values passed to an include, and subsequently leverage that to achieve remote code execution. This makes it possible for unauthenticated threat actors to easily execute code on the server.": "Wtyczka WordPress o nazwie Backup Migration w wersji do 1.3.7 włącznie zawiera podatność umożliwiającą zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "Versions prior to 1.9.2 have a cross-site scripting (XSS) vulnerability that could be exploited when an authenticated user uploads a crafted image file for their avatar that gets rendered as a HTML file on the website.": "LabelStudio w wersji poniżej 1.9.2 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "enumerate the users on a SMTP server by issuing the VRFY/EXPN commands": "Za pomocą komendy VRFY/EXPN można poznać nazwy użytkowników serwera SMTP.",
    "In the module 'Theme Volty CMS Blog' (tvcmsblog) up to versions 4.0.1 from Theme Volty for PrestaShop, a guest can perform SQL injection in affected versions.": "Moduł systemu PrestaShop o nazwie Theme Volty CMS Blog w wersji do 4.0.1 zawiera podatność SQL Injection umożliwiającą atakującemu pobranie całej zawartości bazy danych."
    + UPDATE_HINT,
    "Ricoh default admin credentials were discovered.": "Wykryto urządzenie Ricoh do którego można zalogować się na konto administracyjne domyślnymi danymi.",
    'A website running via IIS on an old .net framework contains a get request vulnerability. Using the the tilde character "~" in the request, an attacker can locate short names of files and folders not normally visible.': "Strony internetowe korzystające z serwera IIS i starej wersji frameworku .NET zawierają podatność umożliwiającą atakującemu poznanie nazw plików które nie są publicznie dostępne."
    + UPDATE_HINT,
    "A vulnerability has been found in TVT DVR TD-2104TS-CL, DVR TD-2108TS-HP, Provision-ISR DVR SH-4050A5-5L(MM) and AVISION DVR AV108T and classified as problematic. This vulnerability affects unknown code of the file /queryDevInfo. The manipulation leads to information disclosure.": "Urządzenia TVT DVR TD-2104TS-CL, DVR TD-2108TS-HP, Provision-ISR DVR SH-4050A5-5L(MM) i AVISION DVR AV108T zawierają podatność umożliwiającą nieuprawniony odczyt niektórych danych.",
    "Headers were tested for remote command injection vulnerabilities.": "Wykryto, że w nagłówku HTTP można umieścić komendy umożliwiające atakującemu zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION,
    "PlaceOS Authentication Service before 1.29.10.0 allows app/controllers/auth/sessions_controller.rb open redirect.": "PlaceOS Authentication Service w wersji poniżej 1.29.10.0 zawiera podatność Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie."
    + UPDATE_HINT,
    "GeoServer is an open source software server written in Java that allows users to share and edit geospatial data. GeoServer includes support for the OGC Filter expression language and the OGC Common Query Language (CQL) as part of the Web Feature Service (WFS) and Web Map Service (WMS) protocols. CQL is also supported through the Web Coverage Service (WCS) protocol for ImageMosaic coverages. Users are advised to upgrade to either version 2.21.4, or version 2.22.2 to resolve this issue. Users unable to upgrade should disable the PostGIS Datastore *encode functions* setting to mitigate ``strEndsWith``, ``strStartsWith`` and ``PropertyIsLike `` misuse and enable the PostGIS DataStore *preparedStatements* setting to mitigate the ``FeatureId`` misuse.": "GeoServer w wersji poniżej 2.21.4 umożliwia atakującemu wykonywanie dowolnych kwerend."
    + UPDATE_HINT,
    "Moodle 3.10 to 3.10.3, 3.9 to 3.9.6, 3.8 to 3.8.8, and earlier unsupported versions contain a cross-site scripting vulnerability via the redirect_uri parameter.": "System Moodle w wersji od 3.10 do 3.10.3, 3.9 do 3.9.6, 3.8 do 3.8.8 i wcześniejszych niewspieranych wersjach zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "HG configuration was detected.": "Wykryto konfigurację systemu Mercurial.",
    "WordPress Plugin WP Statistics 13.0.7  contains an unauthenticated Time based SQL injection vulnerability. The plugin does not sanitize and escape the id parameter before using it in a SQL statement, leading to an unauthenticated blind SQL injection. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.": "Wtyczka WordPress o nazwie WP Statistics w wersji 13.0.7 i potencjalnie wcześniejszych zawiera podatność Time-based SQL injection, umożliwiającą atakującemu pobranie całej zawartości bazy danych.",
    "HTML Injection in GitHub repository froxlor/froxlor prior to 0.10.38.2.": "Repozytorium froxlor/froxlor w wersji poniźej 0.10.38.2 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "WordPress Simple Membership plugin before 4.1.1 contains a reflected cross-site scripting vulnerability. It does not properly sanitize and escape parameters before outputting them back in AJAX actions.": "Wtyczka WordPress o nazwie Simple Membership w wersji poniżej 4.1.1 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "The Node.js application runs in development mode, which can expose sensitive information, such as source code and secrets, depending on the application.": "Wykryto aplikację w technologii Node.js działającą w trybie deweloperskim. Aplikacje działające w tym trybie mogą potencjalnie udostępniać wrażliwe informacje takie jak kod źródłowy czy konfiguracja aplikacji.",
    "The remote LDAP server allows anonymous access": "Wykryto serwer LDAP, który nie wymaga logowania. Rekomendujemy, aby takie zasoby nie były publicznie dostępne.",
    "Jira before version 7.13.4, from version 8.0.0 before version 8.0.4, and from version 8.1.0 before version 8.1.1, allows remote attackers to access files in the Jira webroot under the META-INF directory via local file inclusion.": "System Jira w wersji poniżej 7.13.4, w wersji od 8.0.0 poniżej 8.0.4 i w wersji od 8.1.0 poniżej 8.1.1 umożliwia atakującemu odczytanie plików z dysku."
    + UPDATE_HINT,
    "ThinkPHP has a command execution vulnerability because the multi-language function is enabled and the parameter passing of parameter lang is not strictly filtered. Attackers can use this vulnerability to execute commands.": "ThinkPHP zawiera podatnosć umożliwiającą atakującemu zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "The WP Fastest Cache WordPress plugin before 1.2.2 does not properly sanitise and escape a parameter before using it in a SQL statement, leading to a SQL injection exploitable by unauthenticated users.": "Wtyczka WordPress o nazwie WP Fastest Cache w wersji poniżej 1.2.2 zawiera podatność SQL Injection, umożliwiającą atakującemu pobranie całej zawartości bazy danych."
    + WORDPRESS_UPDATE_HINT,
    "The plugin does not validate a parameter passed to the php extract function when loading templates, allowing an unauthenticated attacker to override the template path to read arbitrary files from the hosts file system. This may be escalated to RCE using PHP filter chains.": "Wtyczka WordPress o nazwie Extensive VC Addons for WPBakery w wersji poniżej 1.9.1 zawiera podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku, a w niektórych sytuacjach - zdalne wykonanie kodu. "
    + RCE_EFFECT_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "Detects anonymous access to SMB shares on a remote server.": "Wykryto, że dostęp do udziału SMB jest możliwy bez uwierzytelnienia.",
    "WordPress Elementor Website Builder plugin before 3.1.4 contains a DOM cross-site scripting vulnerability. It does not sanitize or escape user input appended to the DOM via a malicious hash.": "Wtyczka WordPress o nazwie Elementor Website Builder w wersji poniżej 3.1.4 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "CHIYU BF-430, BF-431 and BF-450M TCP/IP Converter devices contain a cross-site scripting vulnerability due to a lack of sanitization of the input on the components man.cgi, if.cgi, dhcpc.cgi, and ppp.cgi.": "Urządzenia CHIYU BF-430, BF-431 i BF-450M TCP/IP Converter zawierają podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "RTSP was detected.": "Wykryto publicznie dostępny serwer RTSP.",
    "Signing is not required on the remote SMB server. An unauthenticated, remote attacker can exploit this to conduct man-in-the-middle attacks against the SMB server.": "Podpisy wiadomości nie są wymagane na serwerze SMB (SigningRequired: false). Dzięki temu atakujący, który może modyfikować komunikację z serwerem SMB, może uzyskać nieuprawniony dostęp do zasobu.",
    "SSH weak algorithms are outdated cryptographic methods that pose security risks. Identifying and disabling these vulnerable algorithms is crucial for enhancing the overall security of SSH connections.": "Wykryto serwer SSH wspierający słabe/podatne algorytmy kryptograficzne.",
    "javascript/cves/2023/CVE-2023-48795.yaml": "Wykryto implementację protokołu SSH podatną na atak Terrapin, umożliwiający wyłączenie niektórych zabezpieczeń protokołu SSH.",
    "Subrion CMS before 4.1.5.10 has a SQL injection vulnerability in /front/search.php via the $_GET array.": "System Subrion CMS w wersji poniżej 4.1.5.10 zawiera podatność SQL Injection, umożliwiającą atakującemu pobranie całej zawartości bazy danych.",
    "settings.php source code was detected via backup files.": "Wykryto kopię zapasową pliku settings.php."
    + DATA_HIDE_HINT,
    "WordPress Plugin DB Backup 4.5 and possibly prior versions are prone to a local file inclusion vulnerability because they fail to sufficiently sanitize user-supplied input. Exploiting this issue can allow an attacker to obtain sensitive information that could aid in further attacks.": "Wtyczka WordPress o nazwie DB Backup w wersji 4.5 i potencjalnie wcześniejszych zawiera podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. "
    + WORDPRESS_UPDATE_HINT,
    "A directory traversal vulnerability in the dp_img_resize function in php/dp-functions.php in the DukaPress plugin before 2.5.4 for WordPress allows remote attackers to read arbitrary files via a .. (dot dot) in the src parameter to lib/dp_image.php.": "Wtyczka WordPress o nazwie DukaPress w wersji poniżej 2.5.4 zawiera podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. "
    + WORDPRESS_UPDATE_HINT,
    "WordPress WooCommerce < 1.2.7 is susceptible to file download vulnerabilities. The lack of authorization checks in the handle_downloads() function hooked to admin_init() could allow unauthenticated users to download arbitrary files from the blog using a path traversal payload.": "Wtyczka WordPress o nazwie WooCommerce w wersji poniżej 1.2.7 zawiera podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. "
    + WORDPRESS_UPDATE_HINT,
    "A directory traversal vulnerability in the file_get_contents function in downloadfiles/download.php in the WP Content Source Control (wp-source-control) plugin 3.0.0 and earlier for WordPress allows remote attackers to read arbitrary files via a .. (dot dot) in the path parameter.": "Wtyczka WordPress o nazwie WP Content Source Control w wersji 3.0.0 i wcześniejszych zawiera podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. "
    + WORDPRESS_UPDATE_HINT,
    "WordPress Memphis Document Library 3.1.5 is vulnerable to local file inclusion.": "Wtyczka WordPress o nazwie Memphis Document Library w wersji 3.1.5 i potencjalnie wcześniejszych zawiera podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. "
    + WORDPRESS_UPDATE_HINT,
    "Tinymce Thumbnail Gallery 1.0.7 and before are vulnerable to local file inclusion via download-image.php.": "Tinymce Thumbnail Gallery w wersji 1.0.7 i wcześniejszych zawiera podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. "
    + UPDATE_HINT,
    "WordPress Javo Spot Premium Theme `wp-config` was discovered via local file inclusion. This file is remotely accessible and its content available for reading.": "Wykryto szablon WordPress o nazwie Javo Spot Premium w wersji zawierającej podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. "
    + WORDPRESS_UPDATE_HINT,
    "WordPress Oxygen-Theme has a local file inclusion vulnerability via the 'file' parameter of 'download.php'.": "Wykryto szablon WordPress o nazwie Oxygen w wersji zawierającej podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. "
    + WORDPRESS_UPDATE_HINT,
    "WordPress Javo Spot Premium Theme is vulnerable to local file inclusion that allows remote unauthenticated attackers access to locally stored file and return their content.": "Wykryto szablon WordPress o nazwie Javo Spot Premium w wersji zawierającej podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. "
    + WORDPRESS_UPDATE_HINT,
    "WordPress Download Shortcode 0.2.3 is prone to a local file inclusion vulnerability because it fails to sufficiently sanitize user-supplied input. Exploiting this issue may allow an attacker to obtain sensitive information that could aid in further attacks. Prior versions may also be affected.": "Wtyczka WordPress o nazwie Download Shortcode w wersji 0.2.3 i potencjalnie wcześniejszych zawiera podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. "
    + WORDPRESS_UPDATE_HINT,
    "WordPress Hide Security Enhancer version 1.3.9.2 or less is susceptible to a local file inclusion vulnerability which could allow malicious visitors to download any file in the installation.": "Wtyczka WordPress o nazwie Hide Security Enhancer w wersji 1.3.9.2 i wcześniejszych zawiera podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. "
    + WORDPRESS_UPDATE_HINT,
    "WordPress mTheme-Unus Theme is vulnerable to local file inclusion via css.php.": "Wykryto szablon WordPress o nazwie mTheme-Unus w wersji zawierającej podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. "
    + WORDPRESS_UPDATE_HINT,
    "Zoho manageengine is vulnerable to reflected cross-site scripting. This impacts  Zoho ManageEngine Netflow Analyzer before build 123137, Network Configuration Manager before build 123128, OpManager before build 123148, OpUtils before build 123161, and Firewall Analyzer before build 123147 via the parameter 'operation' to /servlet/com.adventnet.me.opmanager.servlet.FailOverHelperServlet.": "Zoho ManageEngine Netflow Analyzer w wersji poniżej 123137, Network Configuration Manager w wersji poniżej 123128, OpManager w wersji poniżej 123148, OpUtils before build 123161, zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "WordPress Brandfolder allows remote attackers to access arbitrary files that reside on the local and remote server and disclose their content.": "Wykryto wtyczkę WordPress o nazwie Brandfolder w wersji zawierającej podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. "
    + WORDPRESS_UPDATE_HINT,
    "Wordpress HB Audio Gallery Lite is vulnerable to local file inclusion.": "Wykryto wtyczkę WordPress o nazwie HB Audio Gallery Lite w wersji zawierającej podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. "
    + WORDPRESS_UPDATE_HINT,
    "WordPress ChurcHope Theme <= 2.1 is susceptible to local file inclusion. The vulnerability is caused by improper filtration of user-supplied input passed via the 'file' HTTP GET parameter to the '/lib/downloadlink.php' script, which is publicly accessible.": "Szablon WordPress o nazwie ChurcHope w wersji do 2.1 włącznie zawiera podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. "
    + WORDPRESS_UPDATE_HINT,
    "WordPress plugin Cherry < 1.2.7 contains an unauthenticated file upload and download vulnerability, allowing attackers to upload and download arbitrary files. This could result in attacker uploading backdoor shell scripts or downloading the wp-config.php file.": "Wtyczka WordPress o nazwie Cherry w wersji poniżej 1.2.7 zawiera podatność umożliwiającą atakującemu zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "WordPress plugin Cherry < 1.2.7 has a vulnerability which enables an attacker to upload files directly to the server. This could result in attacker uploading backdoor shell scripts or downloading the wp-config.php file.": "Wtyczka WordPress o nazwie Cherry w wersji poniżej 1.2.7 zawiera podatność umożliwiającą atakującemu zdalne wykonanie kodu."
    + RCE_EFFECT_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "WordPress Aspose Words Exporter prior to version 2.0 is vulnerable to local file inclusion.": "Wtyczka WordPress o nazwie Aspose Words Exporter w wersji poniżej 2.0 zawiera podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. "
    + WORDPRESS_UPDATE_HINT,
    "WordPress Aspose Importer & Exporter version 1.0 is vulnerable to local file inclusion.": "Wtyczka WordPress o nazwie Aspose Importer & Exporter w wersji 1.0 zawiera podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. "
    + WORDPRESS_UPDATE_HINT,
    "Wordpress Aspose Cloud eBook Generator is vulnerable to local file inclusion.": "Wykryto wtyczkę WordPress o nazwie Aspose Cloud eBook Generator w wersji zawierającej podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. "
    + WORDPRESS_UPDATE_HINT,
    "WordPress Aspose PDF Exporter is vulnerable to local file inclusion.": "Wykryto wtyczkę WordPress o nazwie Aspose PDF Exporter w wersji zawierającej podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku. "
    + WORDPRESS_UPDATE_HINT,
    "Rstudio Shiny Server prior to 1.5.16 is vulnerable to local file inclusion and source code leakage. This can be exploited by appending an encoded slash to the URL.": "Rstudio Shiny Server w wersji poniżej 1.5.16 umożliwia atakującemu odczyt dowolnych plików z dysku, w tym kodu źródłowego aplikacji."
    + UPDATE_HINT,
    "WordPress Simple File List before 3.2.8 is vulnerable to local file inclusion via the eeFile parameter in the ~/includes/ee-downloader.php due to missing controls which make it possible for unauthenticated attackers retrieve arbitrary files.": "Wtyczka WordPress o nazwie Simple File List w wersji poniżej 3.2.8 zawiera podatność umożliwiającą atakującemu odczyt dowolnych plików z dysku."
    + WORDPRESS_UPDATE_HINT,
    "Detects exposed ProjectSend installation page.": "Wykryto publicznie dostępny panel insalacyjny ProjectSend.",
    "Mozilla Pollbot contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.": "Wykryto system Mozilla Pollbot w wersji zawierającej podatność Open Redirect, umożliwiającą atakującemu spreparowanie linku w Państwa domenie który przekierowuje do dowolnej innej strony, w tym np. zawierającej szkodliwe oprogramowanie.",
    "GitLab CE and EE 13.4 through 13.6.2 is susceptible to Information disclosure via GraphQL. User email is visible. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.": "System GitLab CE i EE w wersji od 13.4 do 13.6.2 włącznie umożliwia atakującemu nieuprawniony odczyt adresów e-mail użytkowników i innych danych, które nie powinny być publicznie dostępne."
    + UPDATE_HINT,
    "The Profile Builder User Profile & User Registration Forms WordPress plugin is vulnerable to cross-site scripting due to insufficient escaping and sanitization of the site_url parameter found in the ~/assets/misc/fallback-page.php file which allows attackers to inject arbitrary web scripts onto a pages that executes whenever a user clicks on a specially crafted link by an attacker. This affects versions up to and including 3.6.1..": "Wtyczka WordPress o nazwie The Profile Builder User Profile & User Registration Forms w wersji do 3.6.1 włącznie zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "An unauthenticated remote attacker can leverage this vulnerability to collect registered GitLab usernames, names, and email addresses.": "System GitLab CE/EE w wersji od 13.0 do 14.6.5, 14.7 do 14.7.4 i 14.8 do 14.8 umożliwia atakującemu odczyt danych o użytkownikach, w tym adresów e-mail.",
    "Spark WebUI is exposed to external users without any authentication.": "Wykryto, że panel Spark WebUI jest publicznie dostępny bez uwierzytelnienia.",
    "Web Port 1.19.1 is vulnerable to cross-site scripting via the /log type parameter.": "WebPort w wersji 1.19.1 i potencjalnie wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "http/cves/2018/CVE-2018-20824.yaml": "Zasób WallboardServlet w systemie Jira w wersji poniżej 7.13.1 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "http/cves/2021/CVE-2021-39211.yaml": "GLPI w wersji 9.2 i poniżej 9.5.6 umożliwia atakującemu nieuprawniony dostęp do niektórych informacji."
    + UPDATE_HINT,
    "WordPress True Ranker before version 2.2.4 allows sensitive configuration files such as wp-config.php, to be accessed via the src parameter found in the ~/admin/vendor/datatables/examples/resources/examples.php file via local file inclusion.": "Wtyczka WordPress o nazwie True Ranker w wersji poniżej 2.2.4 umożliwia atakującemu odczyt dowolnych plików z dysku."
    + WORDPRESS_UPDATE_HINT,
    "Wordpress Zedna eBook download prior to version 1.2 was affected by a filedownload.php local file inclusion vulnerability.": "Wtyczka WordPress o nazwie Zedna eBook download w wersji poniżej 1.2 zawiera podatność Local File Inclusion, umożliwiającą atakującemu odczyt dowolnych plików z dysku."
    + WORDPRESS_UPDATE_HINT,
    "WordPress Nevma Adaptive Images plugin before 0.6.67 allows remote attackers to retrieve arbitrary files via the $REQUEST['adaptive-images-settings']['source_file'] parameter in adaptive-images-script.php.": "Wtyczka WordPress o nazwie Nevma Adaptive Images w wersji poniżej 0.6.67 umożliwia atakującemu odczyt dowolnych plików z dysku."
    + WORDPRESS_UPDATE_HINT,
    "PHP remote file inclusion vulnerability in modules/syntax_highlight.php in the Sniplets 1.1.2 and 1.2.2 plugin for WordPress allows remote attackers to execute arbitrary PHP code via a URL in the libpath parameter.": "Wtyczka WordPress o nazwie Sniplets w wersji 1.1.2 i 1.2.2 zawiera podatność Remote File Inclusion, umożliwiającą atakującemu wykonanie dowolnego kodu na serwerze."
    + RCE_EFFECT_DESCRIPTION
    + UPDATE_HINT,
    "Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software is vulnerable to local file inclusion due to directory traversal attacks that can read sensitive files on a targeted system because of a lack of proper input validation of URLs in HTTP requests processed by an affected device. An attacker could exploit this vulnerability by sending a crafted HTTP request containing directory traversal character sequences to an affected device. A successful exploit could allow the attacker to view arbitrary files within the web services file system on the targeted device. The web services file system is enabled when the affected device is configured with either WebVPN or AnyConnect features. This vulnerability cannot be used to obtain access to ASA or FTD system files or underlying operating system (OS) files.": "Wykryto oprogramowanie Cisco Adaptive Security Appliance (ASA) lub Cisco Firepower Threat Defense (FTD) zawierające podatność Directory Traversal, umożliwiającą atakującemu odczyt dowolnych plików z dysku.",
    "CSZ CMS version 1.3.0 suffers from multiple remote blind SQL injection vulnerabilities.": "CSZ CMS w wersji 1.3.0 i potencjalnie wcześniejszych zawiera podatność SQL Injection, umożliwiającą atakującemu pobranie całej zawartości bazy danych."
    + UPDATE_HINT,
    "custom:CVE-2024-5932": "Wtyczka WordPress o nazwie GiveWP w wersji do 3.14.1 włącznie zawiera podatność Object Injection, umożliwiającą atakującemu zdalne wykonanie kodu w niektórych sytuacjach."
    + RCE_EFFECT_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "WordPress GiveWP plugin before 2.17.3 contains a cross-site scripting vulnerability. The plugin does not sanitize and escape the form_id parameter before returning it in the response of an unauthenticated request via the give_checkout_login AJAX action. An attacker can inject arbitrary script in the browser of a user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Wtyczka WordPress o nazwie GiveWP w wersji poniżej 2.17.3 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Directory traversal vulnerability in the Elegant Themes Divi theme for WordPress allows remote attackers to read arbitrary files via a .. (dot dot) in the img parameter in a revslider_show_image action to wp-admin/admin-ajax.php. NOTE: this vulnerability may be a duplicate of CVE-2014-9734.": "Wykryto, że szablon WordPress o nazwie Elegant Themes Divi zawiera podatność Directory Traversal, umożliwiającą atakującemu odczyt dowolnych plików z dysku, w tym zawierających dane dostępowe do bazy danych.",
    "SSH authorized keys file was detected.": "Wykryto plik .ssh/authorized_keys. " + DATA_HIDE_HINT,
    "Magmi 0.7.22 contains a cross-site scripting vulnerability due to insufficient filtration of user-supplied data (prefix) passed to the magmi-git-master/magmi/web/ajax_gettime.php URL.": "Magmi w wersji 0.7.22 i potencjalnie wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Apache ActiveMQ versions 5.0.0 to 5.15.5 are vulnerable to cross-site scripting via the web based administration console on the queue.jsp page. The root cause of this issue is improper data filtering of the QueueFilter parameter.": "Apache ActiveMQ w wersji 5.0.0 do 5.15.5 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Combodo iTop before 2.2.0-2459 contains a cross-site scripting vulnerability in application/dashboard.class.inc.php which allows remote attackers to inject arbitrary web script or HTML via a dashboard title.": "Combodo iTop w wersji poniżej 2.2.0-2459 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Cofax 2.0 RC3 and earlier contains a cross-site scripting vulnerability in search.htm which allows remote attackers to inject arbitrary web script or HTML via the searchstring parameter.": "Cofax 2.0 RC3 i potencjalnie poprzednie wersje zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software are susceptible to directory traversal vulnerabilities that could allow an unauthenticated, remote attacker to obtain read and delete access to sensitive files on a targeted system.": "Wykryto oprogramowanie Cisco Adaptive Security Appliance (ASA) lub Cisco Firepower Threat Defense (FTD) zawierające podatność Directory Traversal, umożliwiającą atakującemu odczyt dowolnych plików z dysku.",
    "Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software are vulnerable to cross-site scripting and could allow an unauthenticated, remote attacker to conduct attacks against a user of the web services interface of an affected device. The vulnerabilities are due to insufficient validation of user-supplied input by the web services interface of an affected device. An attacker could exploit these vulnerabilities by persuading a user of the interface to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the interface or allow the attacker to access sensitive, browser-based information. Note: These vulnerabilities affect only specific AnyConnect and WebVPN configurations. For more information, see the reference links.": "Wykryto oprogramowanie Cisco Adaptive Security Appliance (ASA) lub Cisco Firepower Threat Defense (FTD) zawierające podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Multiple cross-site scripting vulnerabilities in ManageEngine Firewall Analyzer 7.2 allow remote attackers to inject arbitrary web script or HTML via the (1) subTab or (2) tab parameter to createAnomaly.do; (3) url, (4) subTab, or (5) tab parameter to mindex.do; (6) tab parameter to index2.do; or (7) port parameter to syslogViewer.do.": "ManageEngine Firewall Analyzer w wersji 7.2 i potencjalnie wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Grafana instances up to 7.5.11 and 8.1.5 allow remote unauthenticated users to view the snapshot associated with the lowest database key by accessing the literal paths /api/snapshot/:key or /dashboard/snapshot/:key. If the snapshot is in public mode, unauthenticated users can delete snapshots by accessing the endpoint /api/snapshots-delete/:deleteKey. Authenticated users can also delete snapshots by accessing the endpoints /api/snapshots-delete/:deleteKey, or sending a delete request to /api/snapshot/:key, regardless of whether or not the snapshot is set to public mode (disabled by default).": "Grafana w wersji do 7.5.11 (a w gałęzi 8 - do 8.1.5) zawiera podatność umożliwiającą atakującym nieuprawniony dostęp do informacji i wykonywanie operacji."
    + UPDATE_HINT,
    "AWStats is prone to multiple cross-site scripting vulnerabilities because the application fails to properly sanitize user-supplied input.": "Wykryto system AWStats w wersji zawierającej podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Jira Server and Data Center is susceptible to information disclosure. An attacker can enumerate users via the QueryComponentRendererValue!Default.jspa endpoint and thus potentially access sensitive information, modify data, and/or execute unauthorized operations, Affected versions are before version 8.5.13, from version 8.6.0 before 8.13.5, and from version 8.14.0 before 8.15.1.": "Jira Server and Data Center w wersji 8.5.13 i wcześniejszych, pomiędzy 8.6.0 i 8.13.5 i pomiędzy 8.14.0 i 8.15.1 zawiera podatność umożliwiającą pobranie informacji o użytkownikach."
    + UPDATE_HINT,
    "A flaw was found in keycloak in versions prior to 13.0.0. The client registration endpoint allows fetching information about PUBLIC clients (like client secret) without authentication which could be an issue if the same PUBLIC client changed to CONFIDENTIAL later. The highest threat from this vulnerability is to data confidentiality.": "Narzędzie keycloak w wersji poniżej 13.0.0 zawiera podatność umożliwiającą atakujacemu nieuprawniony odczyt poufnych informacji o publicznych klientach.",
    'Moodle Jitsi Meet 2.7 through 2.8.3 plugin contains a cross-site scripting vulnerability via the "sessionpriv.php" module. This allows attackers to craft a malicious URL, which when clicked on by users, can inject JavaScript code to be run by the application.': "Wtyczka Moodle o nazwie Jitsi Meet w wersji 2.7 do 2.8.3 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Behat configuration file was detected.": "wykryto plik konfiguracyjny narzędzia Behat.",
    "Azure Resource Manager deploy file is disclosed.": "Wykryto plik konfiguracyjny narzędzia Azure Resource Manager."
    + DATA_HIDE_HINT,
    "A cross-site scripting vulnerability in remotereporter/load_logfiles.php in Netsweeper 4.0.3 and 4.0.4 allows remote attackers to inject arbitrary web script or HTML via the url parameter.": "Netsweeper w wersji 4.0.4, 4.0.3 i potencjalnie wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    'Clansphere CMS 2011.4 contains an unauthenticated reflected cross-site scripting vulnerability via the "language" parameter.': "Clansphere CMS w wersji 2011.4 i potencjalnie wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "myfactory.FMS before 7.1-912 allows cross-site scripting via the UID parameter.": "myfactory.FMS w wersji poniżej 7.1-912 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "myfactory.FMS before 7.1-912 allows cross-site scripting via the Error parameter.": "myfactory.FMS w wersji poniżej 7.1-912 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Cyberoam NetGenie C0101B1-20141120-NG11VO devices through 2021-08-14 are susceptible to reflected cross-site scripting via the 'u' parameter of ft.php.": "Cyberoam NetGenie C0101B1-20141120-NG11VO w wersi do 2021-08-14 włącznie zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "A cross-site scripting vulnerability in Netsweeper 4.0.4 allows remote attackers to inject arbitrary web script or HTML via the url parameter to webadmin/deny/index.php.": "Netsweeper w wersji 4.0.4 i potencjalnie wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Jira Rainbow.Zen contains a cross-site scripting vulnerability via Jira/secure/BrowseProject.jspa which allows remote attackers to inject arbitrary web script or HTML via the id parameter.": "Wykryto, że narzędzie Jira Rainbow.Zen zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Agentejo Cockpit prior to 0.12.0 is vulnerable to NoSQL Injection via the newpassword method of the Auth controller, which is responsible for displaying the user password reset form.": "Agentejo Cockpit w wersji poniżej 0.12.0 zawiera podatność NoSQL Injection. "
    + UPDATE_HINT,
    "Github Workflow was exposed.": "Wykryto konfigurację workflow serwisu GitHub." + DATA_HIDE_HINT,
    "Adobe ColdFusion Server 8.0.1 and earlier contain multiple cross-site scripting vulnerabilities which allow remote attackers to inject arbitrary web script or HTML via (1) the startRow parameter to administrator/logviewer/searchlog.cfm, or the query string to (2) wizards/common/_logintowizard.cfm, (3) wizards/common/_authenticatewizarduser.cfm, or (4) administrator/enter.cfm.": "Adobe ColdFusion Sever w wersji 8.0.1 i wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Netdata is exposed.": "Wykryto publiczne dostępne metryki systemu Netdata." + DATA_HIDE_HINT,
    "SPIP 3.1.2 and earlier contains a cross-site scripting vulnerability in valider_xml.php which allows remote attackers to inject arbitrary web script or HTML via the var_url parameter in a valider_xml action.": "SPIP w wersji 3.1.2 i wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Triconsole Datepicker Calendar before 3.77 contains a cross-site scripting vulnerability in calendar_form.php. Attackers can read authentication cookies that are still active, which can be used to perform further attacks such as reading browser history, directory listings, and file contents.": "Triconsole Datepicker Calendar w wersji poniżej 3.77 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Multiple cross-site scripting vulnerabilities in Netsweeper before 3.1.10, 4.0.x before 4.0.9, and 4.1.x before 4.1.2 allow remote attackers to inject arbitrary web script or HTML via the (1) server parameter to remotereporter/load_logfiles.php, (2) customctid parameter to webadmin/policy/category_table_ajax.php, (3) urllist parameter to webadmin/alert/alert.php, (4) QUERY_STRING to webadmin/ajaxfilemanager/ajax_get_file_listing.php, or (5) PATH_INFO to webadmin/policy/policy_table_ajax.php/.": "Netsweeper w wersji poniżej 3.1.10, 4.0.x poniżej 4.0.9 i 4.1.x poniżej 4.1.2 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "A cross-site scripting vulnerability in edit-post.php in the Flexible Custom Post Type plugin before 0.1.7 for WordPress allows remote attackers to inject arbitrary web script or HTML via the id parameter.": "Wtyczka WordPress o nazwie Flexible Custom Post Type w wersji poniżej 0.1.7 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes. The vulnerability allows unauthorized access to the sensitive settings exposed by /api/v1/settings endpoint without authentication. All sensitive settings are hidden except passwordPattern.": "Wykryto system Argo CD zawierający podatność umożliwiającą nieuprawniony odczyt ustawień."
    + UPDATE_HINT,
    "SteVe contains a cross-site scripting vulnerability. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.": "Wykryto system SteVe w wersji zawierającej podatność "
    + REFLECTED_XSS_DESCRIPTION,
    "AppCMS 2.0.101 has a cross-site scripting vulnerability in \\templates\\m\\inc_head.php.": "AppCMS w wersji 2.0.101 i potencjalnie wcześniejszych zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION,
    "A cross-site scripting vulnerability in the integrated web server on Siemens SIMATIC S7-1200 CPU devices 2.x and 3.x allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.": "Zintegrowany serwer WWW urządzeń Siemens SIMATIC S7-1200 CPU 2.x i 3.x zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION,
    'An issue was discovered in the Popup Maker plugin before 1.8.13 for WordPress. An unauthenticated attacker can partially control the arguments of the do_action function to invoke certain popmake_ or pum_ methods, as demonstrated by controlling content and delivery of popmake-system-info.txt (aka the "support debug text file").': "Wtyczka WordPress o nazwie Popup Maker w wersji poniżej 1.8.13 zawiera podatność umożliwiającą atakującemu nieuprawniony dostęp do części funkcjonalności."
    + UPDATE_HINT,
    "The Podcast Channels WordPress plugin was affected by an unauthenticated reflected cross-site scripting security vulnerability.": "Wykryto wtyczkę WordPress o nazwie Podcast Channels w wersji zawierającej podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "Dolibarr before 7.0.2  is vulnerable to cross-site scripting and allows remote attackers to inject arbitrary web script or HTML via the foruserlogin parameter to adherents/cartes/carte.php.": "Dolibarr w wersji poniżej 7.0.2 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "WordPress Popup by Supsystic before 1.10.5 did not sanitize the tab parameter of its options page before outputting it in an attribute, leading to a reflected cross-site scripting issue.": "Wtyczka WordPress o nazwie Popup by Supsystic w wersji poniżej 1.10.5 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "Ruby Secret token is exposed.": "Wykryto plik konfiguracyjny secret_token.rb." + DATA_HIDE_HINT,
    "WordPress wpForo Forum plugin before 1.4.12 for WordPress allows unauthenticated reflected cross-site scripting via the URI.": "Wtyczka WordPress o nazwie wpForo w wersji poniżej 1.4.12 zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + WORDPRESS_UPDATE_HINT,
    "The polyfill.io CDN was suspected to serve malware.": "Wykryto skrypty udostępniane z domeny polyfill.io, podejrzewanej o udostępnianie szkodliwego oprogramowania.",
    "The polyfill.io CDN was suspected to serve malware. Note: it's not exploitable anymore": "Wykryto skrypty udostępniane z domeny polyfill.io, podejrzewanej o udostępnianie szkodliwego oprogramowania. Uwaga: ta podatność nie jest już możliwa do wykorzystania - ponieważ jednak domena polyfill.io nie istnieje, rekomendujemy zaprzestanie korzystania ze skryptów tam zamieszczonych.",
    "Magento Server Mass Importer plugin contains multiple cross-site scripting vulnerabilities which allow remote attackers to inject arbitrary web script or HTML via the (1) profile parameter to web/magmi.php or (2) QUERY_STRING to web/magmi_import_run.php.": "Wykryto, że Magento Server Mass Importer zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION,
    "SAP NetWeaver Application Server ABAP, SAP NetWeaver Application Server Java, ABAP Platform, SAP Content Server 7.53 and SAP Web Dispatcher are vulnerable to request smuggling and request concatenation attacks. An unauthenticated attacker can prepend a victim's request with arbitrary data. This way, the attacker can execute functions impersonating the victim or poison intermediary web caches. A successful attack could result in complete compromise of Confidentiality, Integrity and Availability of the system.": "Wykryto oprogramowanie SAP NetWeaver Application Server ABAP, SAP NetWeaver Application Server Java, ABAP Platform, SAP Content Server lub SAP Web Dispatcher w wersji zawierającej podatność HTTP Request Smuggling lub HTTP Request Concatenation, umożliwiającą atakującemu uzyskanie nieuprawnionego dostępu lub zmianę odpowiedzi zwracanych przez serwer innym użytkownikom."
    + UPDATE_HINT,
    "Opensis-Classic Version 8.0 is affected by cross-site scripting. An unauthenticated user can inject and execute JavaScript code through the link_url parameter in Ajax_url_encode.php.": "Opensis-Classic w wersji 8.0 (i potencjalnie wcześniejszych) zawiera podatność "
    + REFLECTED_XSS_DESCRIPTION
    + UPDATE_HINT,
    "custom:cve-2021-26855": "Wykryto podatność ProxyLogon, umożliwiającą atakującemu przejęcie pełnej kontroli nad serwerem poczty."
    + UPDATE_HINT,
    "This instance of Atlassian JIRA is misconfigured to allow an attacker to sign up (create a new account) just by navigating to the signup page that is accessible at the URL /servicedesk/customer/user/signup. After the attacker has created a new account it's possible for him/her to access the support portal.": "Wykryto instancję systemu Jira umożliwiającą rejestrację dowolnym osobom z zewnątrz.",
    "HP iLO serial key was detected.": "Wykryto klucz HP iLO." + DATA_HIDE_HINT,
    "WordPress login panel was detected.": "wykryto panel logowania systemu WordPress.",
    "NPM log file is exposed to external users.": "Wykryto dziennik zdarzeń narzędzia npm.",
    "Wpmudev Wordpress Plugin public key leaked.": "Wykryto klucz publiczny wtyczki WordPress o nazwie wpmudev.",
    "PHP user.ini file is exposed.": "wykryto plik user.ini " + DATA_HIDE_HINT,
    "phpPgAdmin login ipanel was detected.": "wykryto panel logowania narzędzia phpPgAdmin.",
    "OutSystems Service Center login panel was detected.": "Wykryto panel logowania OutSystems Service Center.",
    "[no description] http/exposed-panels/tomcat/tomcat-exposed-docs.yaml": "wykryto dokumentację Apache Tomcat.",
    "An Adminer login panel was detected.": "wykryto panel logowania narzędzia Adminer.",
    "Webalizer panel was detected.": "wykryto panel narzędzia Webalizer.",
    "http/exposed-panels/ghost-panel.yaml": "wykryto panel systemu Ghost",
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
    "google analytics alternative that protects your data and your customers privacy.": "wykryto panel logowania Matomo.",
    "Modoboa login panel was detected.": "wykryto panel logowania narzędia Modoboa.",
    "QmailAdmin login panel was detected.": "wykryto panel logowania QmailAdmin.",
    "Jenkins is an open source automation server.": "wykryto panel logowania systemu Jenkins.",
    "Plesk Onyx login panel was detected.": "wykryto panel logowania Plesk Onyx.",
    "Gogs login panel was detected.": "wykryto panel logowania Gogs.",
    "WildFly welcome page was detected.": "wykryto stronę startową WildFly.",
    "Grafana login panel was detected.": "wykryto panel logowania narzędzia Grafana.",
    "Web Service panel was detected.": "wykryto panel narzędzia Web Service.",
    "DirectAdmin login panel was detected.": "wykryto panel narzędzia DirectAdmin.",
    "Seafile panel was detected.": "wykryto panel Seafile.",
    "Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers. The Empire server is written in Python 3 and is modular to allow operator flexibility. Empire comes built-in with a client that can be used remotely to access the server. There is also a GUI available for remotely accessing the Empire server.": "wykryto panel narzędzia Empire, używanego m. in. do kontroli przejętych systemów w trakcie ataków lub testów bezpieczeństwa.",
    "RStudio panel was detected.": "wykryto panel RStudio.",
    "An Argo CD login panel was discovered.": "wykryto panel Argo CD.",
    "XNAT login panel was detected.": "wykryto panel logowania XNAT.",
    "OCS Inventory login panel was detected.": "wykryto panel logowania narzędzia OCS Inventory.",
    "PaperCut is a print management system. Log in to manage your print quotas, see your print history and configure your system.": "wykryto panel logowania systemu PaperCut.",
    "IBM iNotes login panel was detected.": "wykryto panel logowania systemu IBM iNotes.",
    "An Atlassian Crowd login panel was discovered.": "wykryto panel logowania Atlassian Crowd.",
    "LiveZilla login panel was detected.": "wykryto panel logowania LiveZilla.",
    "HashiCorp Consul Web UI login panel was detected,": "wykryto panel logowania narzędzia Hashicorp Consul.",
    "Drone CI login panel was detected.": "wykryto panel logowania narzędzia Drone CI.",
    "Control Web Panel login panel was detected.": "wykryto panel logowania narzędzia Control Web Panel.",
    "Prometheus panel was detected.": "wykryto panel narzędzia Prometheus.",
    "Hestia Control Panel login was detected.": "wykryto panel logowania narzędzia Hestia Control Panel.",
    "Kibana login panel was detected.": "wykryto panel logowania narzędzia Kibana.",
    "Check for the existence of the ArcGIS Token Service on an ArcGIS server.": "wykryto narzędzie ArcGIS Token Service.",
    "The jUDDI (Java Universal Description, Discovery and Integration) Registry is a core component of the JBoss Enterprise SOA Platform. It is the product's default service registry and comes included as part of the product. In it are stored the addresses (end-point references) of all the services connected to the Enterprise Service Bus. It was implemented in JAXR and conforms to the UDDI specifications.": "wykryto narzędzie jUDDI (Java Universal Description, Discovery and Integration) Registry.",
    'Check for the existence of the "/arcgis/rest/services" path on an ArcGIS server.': "wykryto API narzędzia ArcGIS.",
    "Microsoft SQL Server Reporting Services is vulnerable to a remote code execution vulnerability because it incorrectly handles page requests.": "Wykryto, że system Microsoft SQL Server Reporting Services zawiera podatność umożliwiającą zdalne wykonanie kodu. ",
    "Cisco ASA VPN panel was detected.": "wykryto panel Cisco ASA VPN.",
    "Wowza Streaming Engine Manager panel was detected.": "wykryto panel narzędzia Wowza Streaming Engine Manager.",
    "Splunk SOAR login panel was detected.": "wykryto panel logowania Splunk SOAR.",
    "Proxmox Virtual Environment login panel was detected.": "wykryto panel logowania Proxmox Virtual Environment.",
    "MeshCentral login panel was detected.": "wykryto panel logowania MeshCentral.",
    "Jira Service Desk login panel was detected.": "wykryto panel logowania Jira Service Desk.",
    "Sphider admin login panel was detected.": "wykryto panel administracyjny narzędzia Sphider.",
    "OpenCPU panel was detected.": "wykryto panel OpenCPU.",
    "[no description] http/exposed-panels/home-assistant-panel.yaml": "wykryto panel narzędzia Home Assistant.",
    "Tiny File Manager panel was detected.": "wykryto panel narzędzia Tiny File Manager.",
    "MSPControl login panel was detected.": "wykryto panel narzędzia MSPControl.",
    "ESXi System login panel was detected.": "wykryto panel logowania ESXi System.",
    "3CX Phone System Management Console panel was detected.": "wykryto panel 3CX Phone System Management Console.",
    "3CX Phone System Web Client Management Console panel was detected.": "wykryto panel 3CX Phone System Web Client Management Console.",
    "Kraken Cluster Monitoring Dashboard was detected.": "wykryto panel Kraken Cluster Monitoring Dashboard.",
    "AVideo installer panel was detected.": "wykryto panel instalacyjny narzędzia AVideo.",
    "WHM login panel was detected.": "wykryto panel logowania WHM.",
    "SonicWall Network Security Login panel was detected.": "wykryto panel logowania SonicWall Network Security.",
    "SonicWall Management admin login panel was detected.": "wykryto panel administracyjny SonicWall Management.",
    "Piwigo login panel was detected.": "wykryto panel logowania Piwigo.",
    "D-Link Wireless Router panel was detected.": "wykryto panel routera bezprzewodowego D-Link.",
    "WSO2 Management Console login panel was detected.": "wykryto panel logowania WSO2 Management Console.",
    "Jira Service Desk login panel was detected.": "wykryto panel logowania Jira Service Desk.",
    "ZOHO ManageEngine ServiceDesk panel was detected.": "wykryto panel ZOHO ManageEngine ServiceDesk.",
    "TeamPass panel was detected.": "wykryto panel TeamPass.",
    "Apache Solr admin panel was detected.": "wykryto panel administracyjny Apache Solr.",
    "VMware Workspace ONE UEM Airwatch login panel was detected.": "wyktyro panel logowania VMware Workspace ONE UEM Airwatch.",
    "http/exposed-panels/pritunl-panel.yaml": "wykryto panel Pritunl",
    "Oracle WebLogic login panel was detected.": "wykryto panel logowania Oracle WebLogic.",
    "Gryphon router panel was detected.": "wykryto panel routera Gryphon.",
    "pfSense login panel was detected.": "wykryto panel logowania pfSense.",
    "SonarQube panel was detected.": "wykryto panel SonarQube.",
    "Wazuh - The Open Source Security Platform": "wykryto panel narzędzia Wazuh.",
    "JBoss JMX Management Console login panel was detected.": "wykryto panel logowania JBoss JMX Management Console",
    "Fiori Launchpad login panel was detected.": "wykryto panel logowania Fiori Launchpad.",
    "Palo Alto Networks GlobalProtect login panel was detected.": "wykryto panel logowania Palo Alto Networks GlobalProtect.",
    "Cisco Secure Desktop installation panel was detected.": "wykryto panel instalacyjny Cisco Secure Desktop.",
    "Openfire Admin Console login panel was detected.": "wykryto panel logowania konsoli administracyjnej Openfire.",
    "MinIO Browser login panel was detected.": "wykryto panel logowania MinIO Browser.",
    "noVNC login panel was detected.": "wykryto panel logowania noVNC.",
    "[no description] http/exposed-panels/remedy-axis-login.yaml": "wykryto panel logowania Remedy Axis.",
    "VMware Cloud Director login panel was detected.": "wykryto panel logowania VMWare Cloud Director.",
    "MobileIron login panel was detected.": "wykryto panel logowania MobileIron.",
    "Shell In A Box implements a web server that can export arbitrary command line tools to a web based terminal emulator": "wykryto panel Shell In A Box.",
    "NetScaler AAA login panel was detected.": "wykryto panel logowania NetScaler AAA.",
    "Citrix ADC Gateway login panel was detected.": "wykryto panel logowania Citrix ADC Gateway.",
    "Jalios JCMS login panel was detected.": "wykryto panel logowana Jalios JCMS.",
    "Graphite Browser login panel was detected.": "wykryto panel logowania Graphite Browser.",
    "Lancom router login panel was detected.": "wykryto panel logowania routera Lancom.",
    "Bookstack login panel was detected.": "wykryto panel logowania Bookstack.",
    "LDAP Account Manager login panel was detected.": "wykryto panel logowania LDAP Account Manager.",
    "IBM WebSphere Application Server Community Edition admin login panel was detected.": "wykryto panel logowania IBM WebSphere Application Server Community Edition.",
    "Odoo OpenERP database selector panel was detected.": "wykryto panel wyboru bazy danych narzędzia Odoo OpenERP.",
    "Dynamicweb login panel was detected.": "wykryto panel logowania Dynamicweb.",
    "LibreNMS login panel was detected.": "wykryto panel logowania LibreNMS.",
    "Jenkins API panel was detected.": "wykryto panel API systemu Jenkins.",
    "Joget panel was detected.": "wykryto panel Joget.",
    "[no description] http/exposed-panels/phpldapadmin-panel.yaml": "wykryto panel phpLDAPadmin.",
    "OTOBO login panel was detected.": "wykryto panel logowania OTOBO.",
    "MinIO Console login panel was detected.": "wykryto panel logowania MinIO Console.",
    "Froxlor Server Management login panel was detected.": "wykryto panel logowania Froxlor Server Management.",
    "Versa Director login panel was detected.": "wykryto panel logowania Versa Director.",
    "Versa SD-WAN login panel was detected.": "wykryto panel logowania Versa SD-WAN.",
    "Traefik Dashboard panel was detected.": "wykryto panel Traeifk Dashboard.",
    "Qlik Sense Server panel was detected.": "wykryto panel Qlik Sense Server.",
    "Leostream login panel was detected.": "wykryto panel logowania Leostream.",
    "http/exposed-panels/workresources-rdp.yaml": "wykryto panel RDWeb RemoteApp and Desktop Connections.",
    "Greenbone Security Assistant Web Panel is detected": "wykryto panel Greenbone Security Assistant.",
    "TIBCO Jaspersoft login panel was detected.": "wykryto panel TIBCO Jaspersoft.",
    "SQL Buddy login panel was detected.": "wykryto panel logowania SQL Buddy.",
    "OpenStack Dashboard login panel was detected.": "wykryto panel logowania OpenStack Dashboard.",
    "http/exposed-panels/uptime-kuma-panel.yaml": "wykryto panel Uptime Kuma.",
    "http/exposed-panels/portainer-panel.yaml": "wykryto panel logowania narzędzia Portainer.",
    "Plesk login panel was detected.": "wykryto panel logowania Plesk.",
    "H2 Console Web login panel was detected.": "wykryto panel logowania H2 Console Web.",
    "Redash login panel was detected.": "wykryto panel logowania Redash.",
    "http/exposed-panels/bitwarden-vault-panel.yaml": "wykryto panel Bitwarden Vault.",
    "Bitdefender GravityZone panel was detected.": "wykryto panel Bitdefender GravityZone.",
    "Kerio Connect login panel was detected.": "wykryto panel logowania Kerio Connect.",
    "SphinxOnline Login Panel was detected.": "wykryto panel logowania SphinxOnline.",
    "Sidekiq Dashboard panel was detected.": "wykryto panel Sidekiq Dashboard.",
    "Prometheus metrics page was detected.": "wykryto stronę z metrykami systemu Prometheus.",
    "Asus router login panel was detected.": "wykryto panel logowania routera Asus.",
    "http/exposed-panels/appsuite-panel.yaml": "wykryto panel logowania Appsuite.",
    "F-Secure Policy Manager Server login panel was detected.": "wykryto panel logowania F-Secure Policy Manager Server.",
    "Netdata Dashboard panel was detected.": "wykryto panel Netdata Dashboard.",
    "Netdata panel was detected.": "wykryto panel Netdata.",
    "http/exposed-panels/odoo-panel.yaml": "wykryto panel Odoo.",
    "The Neo4j Browser has been detected.": "wykryto narzędzie Neo4j Browser.",
    "http/exposed-panels/homer-panel.yaml": "wykryto panel systemu Homer",
    "Rundeck login panel was detected.": "wykryto panel logowania Rundeck.",
    "NagVis login panel was detected.": "wykryto panel logowania NagVis.",
    "RD web access panel was discovered.": "wykryto panel Remote Desktop Web Access.",
    "http/exposed-panels/plausible-panel.yaml": "wykryto panel systemu Plausible.",
    "Micro Focus Vibe login panel was detected.": "wykryto panel logowania Micro Focus Vibe.",
    "An Ansible Semaphore login panel was detected.": "wykryto panel logowania Ansible Semaphore.",
    "Centreon login panel was detected.": "wykryto panel logowania Centreon.",
    "[no description] http/exposed-panels/filebrowser-login-panel.yaml": "wykryto panel logowania narzędzia File Browser.",
    "TrueNAS scale is a free and open-source NAS solution": "wykryto panel logowania TrueNAS.",
    "Microsoft Exchange Web Services was detected.": "wykryto panel Microsoft Exchange Web Services.",
    "OpenX login panel was detected. Note that OpenX is now a Revive Adserver.": "wykryto panel logowania OpenX / Revive Adserver.",
    "Passbolt login panel was detected.": "wykryto panel logowania Passbolt.",
    "Sentry login panel was detected.": "wykryto panel logowania Sentry.",
    "A Dahua admin login panel was detected.": "wykryto panel logowania Dahua.",
    "Storybook panel was detected.": "wykryto panel Storybook.",
    "ServiceNow Login Panel was detected.": "wykryto panel logowania Servicenow.",
    "Archibus Web Central login panel was detected.": "wykryto panel logowania Archibus Web Central.",
    "Graylog login panel was detected.": "wykryto panel logowania Graylog.",
    "Login page for Eset Protect": "wykryto panel logowania Eset Protect",
    "OpenNebula login panel was detected.": "wykryto panel logowania OpenNebula.",
    "Metabase login panel was detected.": "wykryto panel logowania Metabase.",
    "[no description] http/exposed-panels/fortinet/forticlientems-panel.yaml": "wykryto panel logowania FortiClient Endpoint Management Server.",
    "Rancher Dashboard was detected.": "wykryto panel Rancher Dashboard.",
    "VMware Cloud Director Availability login panel was detected.": "wykryto panel logowania VMware Cloud Director Availability.",
    "Mitric Checker login panel was detected.": "wykryto panel logowania Mitric Checker.",
    "http/exposed-panels/magento-downloader-panel.yaml": "Wykryto panel Magento Connect Manager pod adresem /downloader/",
    "AWS OpenSearch login page was detected.": "wykryto panel AWS OpenSearch.",
    "Zyxel Firewall panel was detected.": "wykryto panel Zyxel Firewall.",
    "[no description] http/exposed-panels/powerchute-network-panel.yaml": "wykryto panel PowerChute Network Shutdown",
    "BeyondTrust Privileged Remote Access login panel was detected.": "wykryto panel logowania BeyondTrust Privileged.",
    "Proofpoint Protection Server panel was detected.": "wykryto panel Proofpoint Protection Server.",
    "http/exposed-panels/n8n-panel.yaml": "Wykryto panel logowania systemu n8n.",
    "Strapi CMS Documentation login panel was detected.": "wykryto panel logowania Strapi CMS Documentation.",
    "NPM Debug log file exposed.": "Wykryto dziennik z danymi diagnostycznymi narzędzia NPM.",
    "Jboss Seam Debug Page was exposed.": "wykryto stronę z danymi diagnostycznymi Jboss Seam.",
    "go pprof debug page was exposed.": "wykryto stronę z informacjami diagnostycznymi systemu go pprof.",
    "http/exposed-panels/maltrail-panel.yaml": "wykryto panel systemu Mailtrail.",
    "Gargoyle Router Management Utility admin login panel was detected.": "wykryto panel systemu Gargoyle Router Management Utility.",
    "Vigor login panel was detected.": "wykryto panel logowania routera Vigor.",
    "LuCi login panel was detected.": "wykryto panel logowania LuCi.",
    "http/exposed-panels/openwrt-login.yaml": "wykryto panel logowania OpenWRT",
    "TurnKey LAMP Control Panel was detected.": "wykryto panel TurnKey LAMP.",
    "Opache control Panel is exposed.": "Wykryto panel systemu Opcache.",
    "SyncThru Web Service panel was detected.": "wykryto panel SyncThru Web Service.",
    "Detects the Froxlor Server Management Panel installation page.": "wykryto panel instalacyjny systemu zarządzania serwerem Froxlor.",
    "cAdvisor page was detected.": "wykryto stronę systemu cAdvisor.",
    "Sharepoint list was detected because of improper configuration. An anonymous user can access SharePoint Web Services.": "Wykryto, że anonimowy użytkownik ma możliwość odczytu niektórych informacji z systemu Sharepoint.",
    "Oracle Application Server login panel was detected.": "Wykryto panel logowania systemu Oracle Application Server.",
    "ASUS AiCloud Panel was detected.": "wykryto panel ASUS AiCloud.",
    "http/exposed-panels/zte-panel.yaml": "wykryto panel systemu ZTE.",
    "NETGEAR router panel was detected.": "wykryto panel routera Netgear.",
    "Samsung printer panel was detected.": "wykryto panel drukarki Samsung.",
    "http/exposed-panels/woodwing-panel.yaml": "wykryto panel Woodwing Studio Server.",
    "Transmission dashboard was detected.": "wykryto panel systemu Transmission.",
    "AppVeyor configuration page was detected.": "wykryto stronę konfiguracyjną systemu AppVeyor.",
    "An Apache Tomcat instance was detected.": "Wykryto panel Apache Tomcat.",
    "Citrix VPN panel was detected.": "wykryto panel Citrix VPN.",
    "Parallels H-Sphere login panel was detected.": "Wykryto panel logowania Paralels H-Sphere.",
    "WebShell4 login panel was detected.": "Wykryto panel logowania WebShell4.",
    "The Wagtail panel has been detected.": "Wykryto panel Wagtail.",
    "Apache Spark panel was detected.": "Wykryto panel Apache Spark.",
    "An Apache Airflow admin login panel was discovered.": "Wykryto panel logowania Apache Airflow.",
    "Micro Focus Application Lifecycle Management login panel was detected.": "Wykryto panel logowania Micro Focus Application Lifecycle Management.",
    "One Identity Password Manager is a secure password manager that gives enterprises control over password management, policies, and automated reset functions.": "Wykryto panel One Identity Password Manager.",
    "myLittleBackup panel was detected.": "wykryto panel myLittleBackup.",
    "Oracle Business Intelligence login panel was detected.": "Wykryto panel logowania Oracle Business Intelligence.",
    "SecurEnvoy login panel was detected.": "Wykryto panel logowania SecurEnvoy.",
    "Appsmith user login panel was detected.": "Wykryto panel logowania Appsmith.",
    "Parse Dashboard login panel was detected.": "Wykryto panel logowania Parse Dashboard.",
    "AirOS panel was detected.": "Wykryto panel AirOS.",
    "Detects the presence of the Label Studio Login Page.": "Wykryto panel logowania Label Studio.",
    "Freshrss panel has been detected.": "Wykryto panel Freshrss.",
    "Nagios current status page was detected.": "Wykryto stronę diagnostyczną systemu Nagios.",
    "An Adobe Experience Manager login panel was detected.": "Wykryto panel logowania Adobe Experience Manager.",
    "kiali panel was detected.": "wykryto panel kiali.",
    "[no description] http/exposed-panels/qBittorrent-panel.yaml": "wykryto panel qBittorrent.",
    "RabbitMQ Management panel was detected.": "Wykryto panel RabbitMQ Management.",
    "Nexus login panel was detected.": "Wykryto panel logowania systemu Nexus.",
    "Apache Superset login panel was detected.": "Wykryto panel logowania Apache Superset.",
    "A Progress Kemp LoadMaster panel was detected.": "wykryto panel Progress Kemp LoadMaster.",
    "EdgeOS login panel was detected.": "Wykryto panel logowania EdgeOS.",
    "Slurm HPC Dashboard was detected.": "Wykryto panel Slurm HPC.",
    "http/exposed-panels/gitlab-explore.yaml": "Wykryto system GitLab.",
    "Micro Focus Enterprise Server Admin panel was detected.": "Wykryto panel Micro Focus Enterprise Server.",
    "The presence of SAML-based authentication on GitLab instances. SAML is commonly used for Single Sign-On (SSO) integrations, which allows users to authenticate with GitLab using an external Identity Provider (IdP).": "Wykryto panel GitLab SAML.",
    "Micro Focus Filr login panel was detected.": "Wykryto panel logowania Micro Focus Filr.",
    "Camunda login panel was detected.": "Wykryto panel logowania systemu Camunda.",
    "An Authentik search engine was detected.": "Wykryto panel wyszukiwarki Authentik.",
    'Identifies "Logon Error Message" in the SAP Internet Communication Framework which returns a 404 status code.': "Wykryto stronę systemu SAP.",
    "RStudio Sign In panel was detected.": "Wykryto panel logowania RStudio.",
    "Usermin panel was discovered.": "Wykryto panel Usermin.",
    "VMware Workspace ONE UEM Airwatch Self-Service Portal (SSP) login panel was detected.": "Wykryto panel logowania VMware Workspace ONE UEM Airwatch Self-Service Portal (SSP)",
    "Cyberpanel login panel was detected.": "Wykryto panel logowania systemu Cyberpanel.",
    "Thruk Monitoring panel was detected.": "Wykryto panel Thruk Monitoring.",
    "FreeScout panel was discovered.": "Wykryto panel FreeScout.",
    "Akuiteo products was detected.": "Wykryto panel Akuiteo.",
    "YunoHost Admin panel was discovered.": "Wykryto panel YunoHost Admin.",
    "Clockwork Dashboard is exposed.": "Wykryto panel Clockwork Dashboard.",
    "Untangle Administrator is a centralized web-based management console that allows administrators to efficiently configure, monitor, and control various network security and filtering features provided by the Untangle NG Firewall, ensuring robust network protection and policy enforcement.": "Wykryto panel Untangle Administrator.",
    "An Opencast Admin panel was discovered. Opencast is a free and open source solution for automated video capture and distribution at scale.": "Wykryto panel administracyjny Opencast.",
    "An OpenWebUI panel was detected": "Wykryto panel OpenWebUI.",
    "Vaultwarden products was detected.": "Wykryto panel Vaultwarden.",
    "Reolink panel was discovered.": "Wykryto panel Reolink",
    "Reposilite products was detected.": "Wykryto panel systemu Reposilite.",
    "PocketBase Login panel was discovered.": "Wykryto panel logowania PocketBase.",
    "AfterLogic WebMail Login panel was detected.": "Wykryto panel AfterLogic WebMail.",
    "Sensu by Sumo Logic login panel was detected.": "Wykryto panel Sensu by Sumo Logic.",
    "Splunk Enterprise login panel was detected.": "Wykryto panel Splunk Enterprise.",
    "http/exposed-panels/umami-panel.yaml": "Wykryto panel systemu Umami Analytics.",
    "OPNsense panel was detected.": "Wykryto panel OPNSense.",
    "Atlassian Bamboo login panel was detected.": "Wykryto panel Atlassian Bamboo.",
    "Cisco IOS XE login panel was detected.": "Wykryto panel logowania Cisco IOS XE.",
    "An Opentwrt admin login page was discovered.": "Wykryto panel logowania OpenWrt.",
    "http/exposed-panels/macos-server-panel.yaml": "Wykryto panel MacOS Server.",
    "Detects F5 Admin Interfaces.": "Wykryto panel administracyjny F5.",
    "Gira HomeServer 4 login panel was detected.": "Wykryto panel logowania Gira HomeServer 4.",
    "Stirling PDF panel was discovered.": "Wykryto panel Stirling PDF.",
    "JFrog login panel was detected.": "Wykryto panel logowania JFrog.",
    "Oracle Enterprise Manager login panel was detected.": "Wykryto panel logowania Oracle Enterprise Manager.",
    "Zoraxy products was detected.": "Wykryto system Zoraxy.",
    "A lorex panel was detected.": "Wykryto panel lorex.",
    "SteVe login panel was detected.": "wykryto panel logowania SteVe.",
    "NocoDB Login panel was discovered.": "wykryto panel logowania NocoDB.",
}
