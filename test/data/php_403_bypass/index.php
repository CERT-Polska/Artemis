<?php

// The 403-bypass-using-headers template sends the request once per header, with
// the header set to 127.0.0.1, in this order:
//
//   X-Forwarded-For  -> 403
//   X-Remote-IP      -> 403
//   X-Remote-Addr    -> 200 (bypass)
//   X-Real-IP        -> 200 (bypass)
//
// The first two headers check that the template keeps trying after a header
// doesn't work. The last two both bypass, so the template could report the same
// bypass twice; test_403_bypass_workflow checks that it stops at the first one.
$bypassing_headers = array('HTTP_X_REMOTE_ADDR', 'HTTP_X_REAL_IP');

$allowed = false;
foreach ($bypassing_headers as $header) {
    if (isset($_SERVER[$header]) && $_SERVER[$header] == '127.0.0.1') {
        $allowed = true;
    }
}

if (!$allowed) {
    http_response_code(403);
    die('Forbidden');
}

?>

<html>
    <body>
        super secret
        long text (it should have at least 200 characters)
        long text (it should have at least 200 characters)
        long text (it should have at least 200 characters)
        long text (it should have at least 200 characters)
    </body>
</html>
