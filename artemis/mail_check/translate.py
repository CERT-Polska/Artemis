import copy
import re
from enum import Enum
from typing import Callable, List, Optional, Tuple

from .scan import DKIMScanResult, DomainScanResult, ScanResult


class Language(Enum):
    en_US = "en_US"
    pl_PL = "pl_PL"


PLACEHOLDER = "__PLACEHOLDER__"
SKIP_PLACEHOLDER = "__SKIP_PLACEHOLDER__"


TRANSLATIONS = {
    Language.pl_PL: [
        (
            "SPF '~all' or '-all' directive not found. We recommend adding it, as it describes "
            "what should happen with messages that fail SPF verification. For example, "
            "'-all' will tell the recipient server to drop such messages.",
            "Nie znaleziono dyrektywy '~all' lub '-all' w rekordzie SPF. Rekomendujemy jej dodanie, ponieważ "
            "opisuje ona, jak powinny zostać potraktowane wiadomości, które zostaną odrzucone "
            "przez mechanizm SPF. Na przykład, dyrektywa '-all' wskazuje serwerowi odbiorcy, "
            "że powinien odrzucać takie wiadomości.",
        ),
        (
            "Valid SPF record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC "
            "to decrease the possibility of successful e-mail message spoofing.",
            "Nie znaleziono poprawnego rekordu SPF. Rekomendujemy używanie wszystkich trzech mechanizmów: "
            "SPF, DKIM i DMARC, aby zmniejszyć szansę, że sfałszowana wiadomość zostanie zaakceptowana "
            "przez serwer odbiorcy.",
        ),
        (
            "Multiple SPF records found. We recommend leaving only one, as multiple SPF records "
            "can cause problems with some SPF implementations.",
            "Wykryto więcej niż jeden rekord SPF. Rekomendujemy pozostawienie jednego z nich - "
            "obecność wielu rekordów może powodować problemy w działaniu niektórych implementacji mechanizmu SPF.",
        ),
        (
            f"The SPF record's include chain has reference to {PLACEHOLDER} domain that doesn't have an SPF "
            "record. When using directives such as 'include' or 'redirect', remember, that the destination domain "
            "must have a proper SPF record.",
            f"Rekord SPF odwołuje się (być może pośrednio) do domeny {PLACEHOLDER}, która nie zawiera rekordu SPF. "
            "W przypadku odwoływania się do innych domen za pomocą dyrektyw SPF takich jak 'include' lub 'redirect', "
            "domena docelowa powinna również zawierać rekord SPF.",
        ),
        (
            "SPF record causes too many void DNS lookups. Some implementations may require the number of "
            "failed DNS lookups (e.g. ones that reference a nonexistent domain) to be low. The DNS lookups "
            "are caused by directives such as 'mx' or 'include'.",
            "Rekord SPF powoduje zbyt wiele nieudanych zapytań DNS. Niektóre implementacje mechanizmu "
            "SPF wymagają, aby liczba nieudanych zapytań DNS (np. odwołujących się do nieistniejących domen) była "
            "niska. Takie zapytania DNS mogą być spowodowane np. przez dyrektywy SPF 'mx' czy 'include'.",
        ),
        (
            "SPF record includes an endless loop. Please check whether 'include' or 'redirect' directives don't "
            "create a loop where a domain redirects back to itself or earlier domain.",
            "Rekord SPF zawiera nieskończoną pętlę. Prosimy sprawdzić, czy dyrektywy SPF 'include' lub 'redirect' "
            "nie odwołują się z powrotem do tej samej domeny lub do wcześniejszych domen.",
        ),
        (
            "SPF record causes too many DNS lookups. The DNS lookups are caused by directives such as 'mx' or 'include'. "
            "The specification requires the number of DNS lookups to be lower or equal to 10 to decrease load on DNS servers.",
            "Rekord SPF powoduje zbyt wiele zapytań DNS. Zapytania DNS są powodowane przez niektóre dyrektywy SPF, takie jak "
            "'mx' czy 'include'. Spefycikacja wymaga, aby liczba zapytań DNS nie przekraczała 10, aby nie powodować nadmiernego "
            "obciążenia serwerów DNS.",
        ),
        (
            "The ptr mechanism should not be used - https://tools.ietf.org/html/rfc7208#section-5.5",
            "Zgodnie ze specyfikacją SPF, nie należy używać mechanizmu 'ptr'. Pod adresem "
            "https://tools.ietf.org/html/rfc7208#section-5.5 można znaleźć uzasadnienie tej rekomendacji.",
        ),
        (
            "Valid DMARC record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC "
            "to decrease the possibility of successful e-mail message spoofing.",
            "Nie znaleziono poprawnego rekordu DMARC. Rekomendujemy używanie wszystkich trzech mechanizmów: "
            "SPF, DKIM i DMARC, aby zmniejszyć szansę, że sfałszowana wiadomość zostanie zaakceptowana "
            "przez serwer odbiorcy.",
        ),
        (
            "DMARC policy is 'none' and 'rua' is not set, which means that the DMARC setting is not effective.",
            "Polityka DMARC jest ustawiona na 'none' i nie ustawiono odbiorcy raportów w polu 'rua', co "
            "oznacza, że ustawienie DMARC nie będzie skuteczne.",
        ),
        (
            f"The DMARC record must be located at {PLACEHOLDER}, not {PLACEHOLDER}",
            f"Rekord DMARC powinien znajdować się w domenie {PLACEHOLDER}, nie {PLACEHOLDER}.",
        ),
        (
            "There are multiple DMARC records. We recommend leaving only one, as multiple "
            "DMARC records can cause problems with some DMARC implementations.",
            "Wykryto więcej niż jeden rekord DMARC. Rekomendujemy pozostawienie jednego z nich - "
            "obecność wielu rekordów może powodować problemy w działaniu niektórych implementacji "
            "mechanizmu DMARC.",
        ),
        (
            "There is a SPF record instead of DMARC one on the '_dmarc' subdomain.",
            "Zamiast rekordu DMARC wykryto rekord SPF w subdomenie '_dmarc'.",
        ),
        (
            "DMARC record uses an invalid tag. Please refer to https://datatracker.ietf.org/doc/html/rfc7489#section-6.3 "
            "for the list of available tags.",
            "Rekord DMARC zawiera niepoprawne pole. Pod adresem "
            "https://cert.pl/posts/2021/10/mechanizmy-weryfikacji-nadawcy-wiadomosci/#dmarc-pola "
            "znajdziesz opis przykładowych pól, które mogą znaleźć się w takim rekordzie, a w specyfikacji mechanizmu "
            "DMARC pod adresem https://datatracker.ietf.org/doc/html/rfc7489#section-6.3 - opis wszystkich pól.",
        ),
        (
            "DMARC report URI is invalid. The report URI should be an e-mail address prefixed with mailto:.",
            "Adres raportów DMARC jest niepoprawny. Powinien to być adres e-mail rozpoczynający się od mailto:.",
        ),
        (
            "The destination of a DMARC report URI does not indicate that it accepts reports for the domain.",
            "Adres raportów DMARC nie wskazuje, że przyjmuje raporty z tej domeny.",
        ),
        (
            "Subdomain policy (sp=) should be reject for parked domains",
            "Polityka subdomen (sp=) powinna być ustawiona na 'reject' dla domen "
            "niesłużących do wysyłki poczty - serwer odbiorcy powinien odrzucać wiadomości z takich domen.",
        ),
        (
            "Policy (p=) should be reject for parked domains",
            "Polityka (p=) powinna być ustawiona na 'reject' dla domen niesłużących "
            "do wysyłki poczty - serwer odbiorcy powinien odrzucać wiadomości z takich domen.",
        ),
        (
            "Unrelated TXT record found in the '_dmarc' subdomain. We recommend removing it, as such unrelated "
            "records may cause problems with some DMARC implementations.",
            "Znaleziono niepowiązane rekordy TXT w subdomenie '_dmarc'. Rekomendujemy ich usunięcie, ponieważ "
            "niektóre serwery mogą w takiej sytuacji odrzucić konfigurację DMARC jako błędną.",
        ),
        (
            "The domain of the email address in a DMARC report URI is missing MX records. That means, that this domain "
            "may not receive DMARC reports.",
            "Domena adresu e-mail w adresie raportów DMARC nie zawiera rekordów MX. Oznacza to, że raporty DMARC mogą nie być "
            "poprawnie dostarczane.",
        ),
        (
            "DMARC policy is 'none', which means that besides reporting no action will be taken. The policy describes what "
            "action the recipient server should take when noticing a message that doesn't pass the verification. 'quarantine' policy "
            "suggests the recipient server to flag the message as spam and 'reject' policy suggests the recipient "
            "server to reject the message. We recommend using the 'quarantine' or 'reject' policy.\n\n"
            "When testing the DMARC mechanism, to minimize the risk of correct messages not being delivered, "
            "the 'none' policy may be used. Such tests are recommended especially when the domain is used to "
            "send a large number of e-mails using various tools and not delivering a correct message is "
            "unacceptable. In such cases the reports should be closely monitored, and the target setting should "
            "be 'quarantine' or 'reject'.",
            "Polityka DMARC jest ustawiona na 'none', co oznacza, że oprócz raportowania, żadna dodatkowa akcja nie zostanie "
            "wykonana. Polityka DMARC opisuje serwerowi odbiorcy, jaką akcję powinien podjąć, gdy wiadomość nie zostanie "
            "poprawnie zweryfikowana. Polityka 'quarantine' oznacza, że taka wiadomość powinna zostać oznaczona jako spam, a polityka 'reject' - że "
            "powinna zostać odrzucona przez serwer odbiorcy. Rekomendujemy korzystanie z polityki 'quarantine' lub 'reject'.\n\n"
            "W trakcie testów działania mechanizmu DMARC, w celu zmniejszenia ryzyka, że poprawne wiadomości zostaną "
            "odrzucone, może być tymczasowo stosowane ustawienie 'none'. Takie testy są szczególnie zalecane, jeśli "
            "domena służy do wysyłki dużej liczby wiadomości przy użyciu różnych narzędzi, a potencjalne niedostarczenie "
            "poprawnej wiadomości jest niedopuszczalne. W takich sytuacjach raporty powinny być dokładnie monitorowane, "
            "a docelowym ustawieniem powinno być 'quarantine' lub 'reject'.",
        ),
        (
            "rua tag (destination for aggregate reports) not found",
            "Nie znaleziono tagu 'rua' (odbiorca zagregowanych raportów).",
        ),
        (
            "Whitespace in domain name detected. Please provide a correct domain name.",
            "Wykryto białe znaki w nazwie domeny. Prosimy o podanie poprawnej nazwy domeny.",
        ),
        (
            f"Unexpected character in domain detected: {PLACEHOLDER}. Please provide a correct domain name.",
            f"Wykryto błędne znaki w nazwie domeny: {PLACEHOLDER}. Prosimy o podanie poprawnej nazwy domeny.",
        ),
        (
            "Any text after the all mechanism is ignored",
            "Tekst umieszczony po dyrektywie 'all' zostanie zignorowany. Rekomendujemy jego usunięcie, lub, "
            "jeśli jest niezbędnym elementem konfiguracji, umieszczenie przed dyrektywą 'all' rekordu SPF.",
        ),
        (
            "No DKIM signature found",
            "Nie znaleziono podpisu DKIM. Rekomendujemy używanie wszystkich trzech mechanizmów: SPF, DKIM i DMARC, aby "
            "zmniejszyć szansę, że sfałszowana wiadomość zostanie zaakceptowana przez serwer odbiorcy.",
        ),
        (
            "Found an invalid DKIM signature",
            "Znaleziono niepoprawny podpis mechanizmu DKIM.",
        ),
        (
            "SPF records containing macros aren't supported by the system yet.",
            "Rekordy SPF zawierające makra nie są jeszcze wspierane przez serwis https://bezpiecznapoczta.cert.pl.",
        ),
        (
            f"The resolution lifetime expired after {PLACEHOLDER}",
            "Przekroczono czas oczekiwania na odpowiedź serwera DNS. Prosimy spróbować jeszcze raz.",
        ),
        (
            f"DMARC record at root of {PLACEHOLDER} has no effect",
            f"Rekord DMARC w domenie '{PLACEHOLDER}' (zamiast w subdomenie '_dmarc') nie zostanie uwzględniony.",
        ),
        (
            "Found a DMARC record that starts with whitespace. Please remove the whitespace, as some "
            "implementations may not process it correctly.",
            "Wykryto rekord DMARC zaczynający się od spacji lub innych białych znaków. Rekomendujemy ich "
            "usunięcie, ponieważ niektóre serwery pocztowe mogą nie zinterpretować takiego rekordu poprawnie.",
        ),
        (
            f"{PLACEHOLDER} does not have any MX records",
            f"Rekord SPF w domenie {PLACEHOLDER} korzysta z dyrektywy SPF 'mx', lecz nie wykryto rekordów MX, w związku "
            "z czym ta dyrektywa nie zadziała poprawnie.",
        ),
        (
            f"{PLACEHOLDER} does not have any A/AAAA records",
            f"Rekord SPF w domenie {PLACEHOLDER} korzysta z dyrektywy SPF 'a', lecz nie wykryto rekordów A/AAAA, w związku "
            "z czym ta dyrektywa nie zadziała poprawnie.",
        ),
        (
            f"{PLACEHOLDER} does not indicate that it accepts DMARC reports about {PLACEHOLDER} - Authorization record not found: {PLACEHOLDER}",
            f"Domena {PLACEHOLDER} nie wskazuje, że przyjmuje raporty DMARC na temat domeny {PLACEHOLDER} - nie wykryto rekordu autoryzacyjnego. "
            "Więcej informacji na temat rekordów autoryzacyjnych, czyli rekordów służących do zezwolenia na wysyłanie raportów DMARC do innej "
            "domeny, możńa przeczytać pod adresem https://dmarc.org/2015/08/receiving-dmarc-reports-outside-your-domain/ .",
        ),
        (
            "SPF type DNS records found. Use of DNS Type SPF has been removed in the standards track version of SPF, RFC 7208. These records "
            f"should be removed and replaced with TXT records: {PLACEHOLDER}",
            "Wykryto rekordy DNS o typie SPF. Wykorzystanie rekordów tego typu zostało usunięte ze standardu – powinny zostać zastąpione rekordami "
            "TXT. Obecność rekordów SPF nie stanowi wprost zagrożenia (jeśli obecne są również poprawne rekordy TXT), ale może prowadzić do pomyłek "
            "(np. w sytuacji, gdy administrator wyedytuje tylko jeden z rekordów).",
        ),
        (
            "Requested to scan a domain that is a public suffix, i.e. a domain such as .com where anybody could "
            "register their subdomain. Such domain don't have to have properly configured e-mail sender verification "
            "mechanisms. Please make sure you really wanted to check such domain and not its subdomain.",
            "Sprawdzają Państwo domenę z listy Public Suffix List (https://publicsuffix.org/) czyli taką jak .pl, gdzie  "
            "różne podmioty mogą zarejestrować swoje subdomeny. Takie domeny nie muszą mieć skonfigurowanych mechanizmów "
            "weryfikacji nadawcy poczty - konfigurowane są one w subdomenach. Prosimy o weryfikację nazwy sprawdzanej domeny.",
        ),
        (
            "Requested to scan a top-level domain. Top-level domains don't have to have properly configured e-mail sender "
            "verification mechanisms. Please make sure you really wanted to check such domain and not its subdomain."
            "Besides, the domain is not known to the Public Suffix List (https://publicsuffix.org/) - please verify whether "
            "it is correct.",
            "Sprawdzają Państwo domenę najwyższego poziomu. Domeny najwyższego poziomu nie muszą mieć "
            "skonfigurowanych mechanizmów weryfikacji nadawcy poczty - konfigurowane są one w subdomenach. Prosimy "
            "o weryfikację nazwy sprawdzanej domeny. Domena nie występuje również na Public Suffix List "
            "(https://publicsuffix.org/) - prosimy o weryfikację jej poprawności.",
        ),
        (
            "Please provide a correct domain name.",
            "Proszę podać poprawną nazwę domeny.",
        ),
        (
            f"Failed to retrieve MX records for the domain of {PLACEHOLDER} email address {PLACEHOLDER} - All nameservers failed to answer the query {PLACEHOLDER}",
            f"Nie udało się odczytać rekordów MX domeny adresu e-mail w dyrektywie {PLACEHOLDER}: {PLACEHOLDER} - serwery nazw nie odpowiedziały poprawnie na zapytanie.",
        ),
        (
            f"All nameservers failed to answer the query {PLACEHOLDER}. IN {PLACEHOLDER}",
            f"Żaden z przypisanych serwerów nazw domen nie odpowiedział na zapytanie dotyczące domeny {PLACEHOLDER}.",
        ),
        (
            f"{PLACEHOLDER}: Expected {PLACEHOLDER} at position {PLACEHOLDER} (marked with {PLACEHOLDER}) in: {PLACEHOLDER}",
            f"{SKIP_PLACEHOLDER}{SKIP_PLACEHOLDER}Rekord nie ma poprawnej składni. Błąd występuje na przybliżonej pozycji "
            f"{PLACEHOLDER} (oznaczonej znakiem {PLACEHOLDER}) w rekordzie '{PLACEHOLDER}'",
        ),
        (
            "the p tag must immediately follow the v tag",
            "Tag p (polityka DMARC) musi następować bezpośrednio po tagu v (wersji DMARC).",
        ),
        (
            'The record is missing the required policy ("p") tag',
            "Rekord nie zawiera tagu p, opisującego politykę - czyli akcję, która powinna zostać wykonana, gdy wiadomość nie "
            "zostanie zweryfikowana poprawnie przy użyciu mechanizmu DMARC.",
        ),
        (
            f"{PLACEHOLDER} is not a valid ipv4 value{PLACEHOLDER}",
            f"{PLACEHOLDER} nie jest poprawnym adresem IPv4.",
        ),
        (
            f"{PLACEHOLDER} is not a valid ipv6 value{PLACEHOLDER}",
            f"{PLACEHOLDER} nie jest poprawnym adresem IPv6.",
        ),
        (
            "Some DMARC reporters might not send to more than two rua URIs",
            "Niektóre implementacje DMARC mogą nie wysłać raportów do więcej niż dwóch odbiorców podanych w polu 'rua'.",
        ),
        (
            "Some DMARC reporters might not send to more than two ruf URIs",
            "Niektóre implementacje DMARC mogą nie wysłać raportów do więcej niż dwóch odbiorców podanych w polu 'ruf'.",
        ),
        (
            f"The domain {PLACEHOLDER} does not exist",
            f"Domena {PLACEHOLDER} nie istnieje.",
        ),
        (
            f"{PLACEHOLDER} is not a valid DMARC report URI - please make sure that the URI begins with a schema such as mailto:",
            f"{PLACEHOLDER} nie jest poprawnym odbiorcą raportów DMARC - jeśli raporty DMARC mają być przesyłane na adres e-mail, "
            "należy poprzedzić go przedrostkiem 'mailto:'.",
        ),
        (
            f"{PLACEHOLDER} is not a valid DMARC report URI",
            f"{PLACEHOLDER} nie jest poprawnym odbiorcą raportów DMARC.",
        ),
        (
            f"{PLACEHOLDER} is not a valid DMARC tag",
            f"'{PLACEHOLDER}' nie jest poprawnym tagiem DMARC.",
        ),
        (
            f"Tag {PLACEHOLDER} must have one of the following values: {PLACEHOLDER} - not {PLACEHOLDER}",
            f"Tag {PLACEHOLDER} powinien mieć wartość spośród: {PLACEHOLDER} - wartość '{PLACEHOLDER}' nie jest dopuszczalna.",
        ),
        (
            "pct value is less than 100. This leads to inconsistent and unpredictable policy "
            "enforcement. Consider using p=none to monitor results instead",
            "Wartość tagu 'pct' wynosi mniej niż 100. Oznacza to, ze mechanizm DMARC zostanie "
            "zastosowany do mniej niż 100% wiadomości, a więc konfiguracja nie będzie spójnie "
            "egzekwowana. W celu monitorowania konfiguracji DMARC przed jej finalnym wdrożeniem "
            "rekomendujemy użycie polityki 'none' i monitorowanie przychodzących raportów DMARC.",
        ),
        (
            "pct value must be an integer between 0 and 100",
            "Wartość 'pct' (procent e-maili, do których zostanie zastosowana polityka DMARC) powinna "
            "być liczbą całkowitą od 0 do 100.",
        ),
        (
            f"Duplicate include: {PLACEHOLDER}",
            f"Domena {PLACEHOLDER} występuje wielokrotnie w tagu 'include'.",
        ),
        (
            "When 1 is present in the fo tag, including 0 is redundant",
            "Jeśli w tagu 'fo' (określającym, kiedy wysyłać raport DMARC) jest włączona opcja 1 (oznaczająca, że raport jest "
            "wysyłany jeśli wiadomość nie jest poprawnie zweryfikowana przez mechanizm SPF lub DKIM, nawet, jeśli "
            "została zweryfikowana przez drugi z mechanizmów), opcja 0 (tj. wysyłka raportów, gdy wiadomość zostanie "
            "zweryfikowana negatywnie przez oba mechanizmy) jest zbędna.",
        ),
        (
            "Including 0 and 1 fo tag values is redundant",
            "Jeśli w tagu 'fo' (określającym, kiedy wysyłać raport DMARC) jest włączona opcja 1 (oznaczająca, że raport jest "
            "wysyłany jeśli wiadomość nie jest poprawnie zweryfikowana przez mechanizm SPF lub DKIM, nawet, jeśli "
            "została zweryfikowana przez drugi z mechanizmów), opcja 0 (tj. wysyłka raportów, gdy wiadomość zostanie "
            "zweryfikowana negatywnie przez oba mechanizmy) jest zbędna.",
        ),
        (
            f"{PLACEHOLDER} is not a valid option for the DMARC {PLACEHOLDER} tag",
            f"'{PLACEHOLDER}' nie jest poprawną opcją tagu '{PLACEHOLDER}'",
        ),
        # dkimpy messages
        (
            f"{PLACEHOLDER} value is not valid base64 {PLACEHOLDER}",
            f"Wartość {PLACEHOLDER} nie jest poprawnie zakodowana algorytmem base64 {PLACEHOLDER}",
        ),
        (
            f"{PLACEHOLDER} value is not valid {PLACEHOLDER}",
            f"Wartość {PLACEHOLDER} nie jest poprawna {PLACEHOLDER}",
        ),
        (
            f"missing {PLACEHOLDER}",
            f"Brakujące pole {PLACEHOLDER}",
        ),
        (
            f"unknown signature algorithm: {PLACEHOLDER}",
            f"Nieznany algorytm podpisu DKIM: {PLACEHOLDER}",
        ),
        (
            f"i= domain is not a subdomain of d= {PLACEHOLDER}",
            f"Domena w polu i= nie jest subdomeną domeny w polu d= {PLACEHOLDER}",
        ),
        (
            f"{PLACEHOLDER} value is not a decimal integer {PLACEHOLDER}",
            f"Wartość w polu {PLACEHOLDER} nie jest liczbą {PLACEHOLDER}",
        ),
        (
            f"q= value is not dns/txt {PLACEHOLDER}",
            f"Wartość w polu q= nie jest równa 'dns/txt' {PLACEHOLDER}",
        ),
        (
            f"v= value is not 1 {PLACEHOLDER}",
            f"Wartość w polu v= nie jest równa 1 {PLACEHOLDER}",
        ),
        (
            f"t= value is in the future {PLACEHOLDER}",
            f"Czas w polu t= jest w przyszłości {PLACEHOLDER}",
        ),
        (
            f"x= value is past {PLACEHOLDER}",
            f"Czas w polu x= jest w przeszłości {PLACEHOLDER}",
        ),
        (
            f"x= value is less than t= value {PLACEHOLDER}",
            f"Czas w polu x= jest wcześniejszy niż w polu t= {PLACEHOLDER}",
        ),
        (
            f"Unexpected characters in RFC822 header: {PLACEHOLDER}",
            f"Nieoczekiwane znaki w nagłówku RFC822: {PLACEHOLDER}",
        ),
        (
            f"missing public key: {PLACEHOLDER}",
            f"Brakujący klucz publiczny: {PLACEHOLDER}",
        ),
        (
            "bad version",
            "Niepoprawna wersja",
        ),
        (
            f"could not parse ed25519 public key {PLACEHOLDER}",
            f"Nie udało się przetworzyć klucza publicznego ed25519 {PLACEHOLDER}",
        ),
        (
            f"incomplete RSA public key: {PLACEHOLDER}",
            f"Niekompletny klucz publiczny RSA: {PLACEHOLDER}",
        ),
        (
            f"could not parse RSA public key {PLACEHOLDER}",
            f"Nie udało się przetworzyć klucza publicznego RSA {PLACEHOLDER}",
        ),
        (
            f"unknown algorithm in k= tag: {PLACEHOLDER}",
            f"Nieznana nazwa algorytmu w polu k=: {PLACEHOLDER}",
        ),
        (
            f"unknown service type in s= tag: {PLACEHOLDER}",
            f"Nieznany typ usługi w polu s=: {PLACEHOLDER}",
        ),
        (
            "digest too large for modulus",
            "Podpis jest dłuższy niż dopuszczają użyte parametry algorytmu szyfrującego.",
        ),
        (
            f"digest too large for modulus: {PLACEHOLDER}",
            f"Podpis jest dłuższy niż dopuszczają użyte parametry algorytmu szyfrującego: {PLACEHOLDER}.",
        ),
        (
            f"body hash mismatch (got b'{PLACEHOLDER}', expected b'{PLACEHOLDER}')",
            f"Niepoprawna suma kontrolna treści wiadomości (otrzymano '{PLACEHOLDER}', oczekiwano '{PLACEHOLDER}').",
        ),
        (
            f"public key too small: {PLACEHOLDER}",
            f"Za mały klucz publiczny: {PLACEHOLDER}.",
        ),
        (
            f"Duplicate ARC-Authentication-Results for instance {PLACEHOLDER}",
            f"Wykryto wiele nagłówków ARC-Authentication-Results dla instancji {PLACEHOLDER}.",
        ),
        (
            f"Duplicate ARC-Message-Signature for instance {PLACEHOLDER}",
            f"Wykryto wiele nagłówków ARC-Message-Signature dla instancji {PLACEHOLDER}.",
        ),
        (
            f"Duplicate ARC-Seal for instance {PLACEHOLDER}",
            f"Wykryto wiele nagłówków ARC-Seal dla instancji {PLACEHOLDER}.",
        ),
        (
            f"Incomplete ARC set for instance {PLACEHOLDER}",
            f"Niekompletny zestaw nagłówków ARC dla instancji {PLACEHOLDER}.",
        ),
        (
            "h= tag not permitted in ARC-Seal header field",
            "Tag h= nie jest dozwolony w nagłówku ARC-Seal.",
        ),
        # from previous runs, where different translations were used
        (
            "SPF record is not syntactically correct. Please closely inspect its syntax.",
            "Rekord SPF nie ma poprawnej składni. Prosimy o jego dokładną weryfikację.",
        ),
        (
            "DMARC record is not syntactically correct. Please closely inspect its syntax.",
            "Rekord DMARC nie ma poprawnej składni. Prosimy o jego dokładną weryfikację.",
        ),
        (
            "The SPF record references a domain that doesn't have an SPF record. When using directives such "
            "as 'include' or 'redirect', remember, that the destination domain should have a proper SPF record.",
            "Rekord SPF odwołuje się do domeny, która nie zawiera rekordu SPF. W przypadku odwoływania się do "
            "innych domen za pomocą dyrektyw SPF takich jak 'include' lub 'redirect', domena docelowa powinna również "
            "zawierać rekord SPF.",
        ),
    ]
}


def translate(
    message: str,
    dictionary: List[Tuple[str, str]],
    nonexistent_translation_handler: Optional[Callable[[str], str]] = None,
) -> str:
    """Translates message according to a dictionary.

    For example, for the following dictionary:

    [
        (f"Input message one {PLACEHOLDER}.", f"Output message one {PLACEHOLDER}."),
        (f"Input message two {PLACEHOLDER}.", f"Output message two {PLACEHOLDER}."),
    ]

    message "Input message one 1234." will get translated to "Output message one 1234.".

    *note* the "from" and "to" messages must have the same number of placeholders -
    and will have the same order of placeholders.
    """
    for m_from, m_to in dictionary:
        pattern = "^" + re.escape(m_from).replace(PLACEHOLDER, "(.*)") + "$"
        regexp_match = re.match(pattern, message)

        # a dictionary rule matched the message
        if regexp_match:
            result = m_to
            for matched in regexp_match.groups():
                placeholder_index = result.index(PLACEHOLDER) if PLACEHOLDER in result else len(result)
                skip_placeholder_index = result.index(SKIP_PLACEHOLDER) if SKIP_PLACEHOLDER in result else len(result)

                if placeholder_index < skip_placeholder_index:
                    # replace first occurence of placeholder with the matched needle
                    result = result.replace(PLACEHOLDER, matched, 1)
                elif skip_placeholder_index < placeholder_index:
                    result = result.replace(SKIP_PLACEHOLDER, "", 1)
            return result

    if nonexistent_translation_handler:
        return nonexistent_translation_handler(message)
    else:
        raise NotImplementedError(f"Unable to translate {message}")


def _(
    message: str,
    language: Language,
    nonexistent_translation_handler: Optional[Callable[[str], str]] = None,
) -> str:
    if language == Language.en_US:
        return message

    return translate(
        message,
        TRANSLATIONS[language],
        nonexistent_translation_handler=nonexistent_translation_handler,
    )


def _translate_domain_result(
    domain_result: DomainScanResult,
    language: Language,
    nonexistent_translation_handler: Optional[Callable[[str], str]] = None,
) -> DomainScanResult:
    new_domain_result = copy.deepcopy(domain_result)
    new_domain_result.spf.errors = [
        _(error, language, nonexistent_translation_handler) for error in domain_result.spf.errors
    ]
    new_domain_result.spf.warnings = [
        _(warning, language, nonexistent_translation_handler) for warning in domain_result.spf.warnings
    ]
    new_domain_result.dmarc.errors = [
        _(error, language, nonexistent_translation_handler) for error in domain_result.dmarc.errors
    ]
    new_domain_result.dmarc.warnings = [
        _(warning, language, nonexistent_translation_handler) for warning in domain_result.dmarc.warnings
    ]
    new_domain_result.warnings = [
        _(warning, language, nonexistent_translation_handler) for warning in new_domain_result.warnings
    ]
    return new_domain_result


def _translate_dkim_result(
    dkim_result: DKIMScanResult,
    language: Language,
    nonexistent_translation_handler: Optional[Callable[[str], str]] = None,
) -> DKIMScanResult:
    new_dkim_result = copy.deepcopy(dkim_result)
    new_dkim_result.errors = [_(error, language, nonexistent_translation_handler) for error in dkim_result.errors]
    new_dkim_result.warnings = [
        _(warning, language, nonexistent_translation_handler) for warning in dkim_result.warnings
    ]
    return new_dkim_result


def translate_scan_result(
    scan_result: ScanResult,
    language: Language,
    nonexistent_translation_handler: Optional[Callable[[str], str]] = None,
) -> ScanResult:
    return ScanResult(
        domain=_translate_domain_result(scan_result.domain, language, nonexistent_translation_handler)
        if scan_result.domain
        else None,
        dkim=_translate_dkim_result(scan_result.dkim, language, nonexistent_translation_handler)
        if scan_result.dkim
        else None,
        timestamp=scan_result.timestamp,
        message_timestamp=scan_result.message_timestamp,
    )
