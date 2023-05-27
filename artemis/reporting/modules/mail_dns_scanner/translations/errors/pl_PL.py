from artemis.reporting.translations import PLACEHOLDER

# Sometimes the strings are split into two even if they can be written in one line
# because this file is synced with an internal repository which has different line
# length constraints.
TRANSLATIONS = [
    (
        "SPF ~all or -all directive not found",
        "Nie znaleziono dyrektywy ~all lub -all w rekordzie SPF",
    ),
    (
        "Valid SPF record not found",
        "Nie znaleziono poprawnego rekordu SPF",
    ),
    ("Multiple SPF records found", "Wykryto wiele rekordów SPF"),
    (
        "SPF record not found in domain referenced from other SPF record",
        "Nie znaleziono rekordu SPF w domenie do której odwołuje się rekord SPF",
    ),
    (
        "SPF record causes too many void DNS lookups",
        "Rekord SPF powoduje zbyt wiele zapytań DNS o nieistniejące rekordy A i MX",
    ),
    (
        "SPF record includes an endless loop",
        "Rekord SPF zawiera nieskończoną pętlę",
    ),
    (
        "SPF record is not syntatically correct",
        "Rekord SPF nie ma poprawnej składni",
    ),
    (
        "SPF record includes too many DNS lookups",
        "Rekord SPF zawiera zbyt wiele zapytań DNS",
    ),
    (
        "The ptr mechanism should not be used - " "https://tools.ietf.org/html/rfc7208#section-5.5",
        "Zgodnie z https://tools.ietf.org/html/rfc7208#section-5.5, " "nie należy używać mechanizmu ptr",
    ),
    (
        "Valid DMARC record not found",
        "Nie znaleziono poprawnego rekordu DMARC",
    ),
    (
        "DMARC policy is none and rua is not set, which means that the " "DMARC setting is not effective.",
        "Polityka DMARC jest ustawiona na 'none' i nie ustawiono odbiorcy "
        "raportów w polu 'rua', co oznacza, że ustawienie DMARC nie będzie "
        "skuteczne.",
    ),
    (
        "DMARC record should be stored in the `_dmarc` subdomain",
        "Rekord DMARC powinien się znajdować w subdomenie '_dmarc'",
    ),
    (
        "There are multiple DMARC records",
        "Wykryto więcej niż jeden rekord DMARC",
    ),
    (
        "There is a SPF record instead of DMARC one",
        "Zamiast rekordu DMARC wykryto rekord SPF",
    ),
    (
        "DMARC record is not syntatically correct",
        "Rekord DMARC nie ma poprawnej składni",
    ),
    (
        "DMARC record uses an invalid tag",
        "Rekord DMARC używa niepoprawnego tagu",
    ),
    (
        "DMARC report URI is invalid",
        "Adres raportów DMARC jest niepoprawny",
    ),
    (
        "The destination of a DMARC report URI does not " "indicate that it accepts reports for the domain",
        "Adres raportów DMARC nie wskazuje, że przyjmuje raporty z tej domeny",
    ),
    (
        "Subdomain policy (sp=) should be reject for parked domains",
        "Polityka subdomen (sp=) powinna być ustawiona na 'reject' dla domen " "niesłużących do wysyłki poczty",
    ),
    (
        "Policy (p=) should be reject for parked domains",
        "Polityka (p=) powinna być ustawiona na 'reject' dla domen niesłużących " "do wysyłki poczty",
    ),
    (
        "Unrelated TXT record found",
        "Znaleziono niepowiązane rekordy TXT",
    ),
    (
        "A email address in a DMARC report URI is missing MX records",
        "Domena adresu e-mail w adresie raportów DMARC nie zawiera rekordów MX",
    ),
    (
        "DMARC policy is none, which means that besides reporting " "no action will be taken",
        "Polityka DMARC jest ustawiona na 'none', co oznacza, że oprócz "
        "raportowania, żadna dodatkowa akcja nie zostanie wykonana",
    ),
    (
        "rua tag (destination for aggregate reports) not found",
        "Nie znaleziono tagu 'rua' (odbiorca zagregowanych raportów)",
    ),
    (
        "Whitespace in domain name detected",
        "Wykryto białe znaki w nazwie domeny",
    ),
    (
        f"Unexpected character in domain detected: {PLACEHOLDER}",
        f"Wykryto błędne znaki w nazwie domeny: {PLACEHOLDER}",
    ),
]
