<?php
// An open redirect in `goto`, a parameter of the site itself that Artemis only
// learns about from the link on the homepage. The DAST target built from that
// link carries it together with 100+ wordlist parameters, and the finding's
// matched-at URL has the payload in many of them.
//
// Only `goto` matters, so the PoC URL must be shortened to `?goto=...` rather
// than kept whole.
//
// The link itself (an empty `goto`) renders a page instead of redirecting: the
// crawler does not report a link whose response is a redirect, so the DAST
// target would never be built from it.
$goto = $_GET["goto"] ?? "";
if ($goto === "") {
    echo "Where to?";
} else {
    header("Location: " . $goto);
}
