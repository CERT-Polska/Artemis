<?php
// A reflected XSS that needs two parameters: `search` is echoed back only when
// `login` is also present.
//
// Nuclei's single fuzzing mode mutates one parameter per request but keeps
// sending the others, so it reports this finding against `search` alone. A PoC
// URL shortened to just `?search=...` would therefore no longer reproduce it -
// this app exists to make sure Artemis notices that and keeps the full URL.
//
// Both parameter names come from artemis/modules/data/dast_params/xss.txt,
// otherwise Artemis would never put them in the DAST target in the first place.
if (isset($_GET["login"])) {
    echo "Login failed: " . $_GET["search"];
}
