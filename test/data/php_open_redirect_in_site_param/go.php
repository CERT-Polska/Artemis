<?php
// An open redirect in `goto`, a parameter of the site itself that Artemis only
// learns about from the link on the homepage. The DAST target built from that
// link carries it together with 100+ wordlist parameters, and the finding's
// matched-at URL has the payload in many of them.
//
// Only `goto` matters, so the PoC URL must be shortened to `?goto=...` rather
// than kept whole.
//
// The link itself (`goto=home`) renders a page instead of redirecting: the
// crawler does not report a link whose response is a redirect, so the DAST
// target would never be built from it. The value must not be empty either,
// as an empty parameter is dropped when the DAST target is built.
$goto = $_GET["goto"] ?? "home";
if ($goto === "home") {
    echo "Home";
} else {
    header("Location: " . $goto);
}
