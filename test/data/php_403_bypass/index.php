<?php

// Only the last two headers the template tries bypass the 403, so the template
// has to move past the ones that don't work and stop at the first one that does.
$remote_addr = $_SERVER['HTTP_X_REMOTE_ADDR'] ?? '';
$real_ip = $_SERVER['HTTP_X_REAL_IP'] ?? '';
if ($remote_addr != '127.0.0.1' && $real_ip != '127.0.0.1') {
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
