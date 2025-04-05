<?php

if (!isset($_SERVER['HTTP_X_REAL_IP']) || $_SERVER['HTTP_X_REAL_IP'] != '127.0.0.1') {
    http_response_code(403);
    die('Forbidden');
}

?>

<html>
    <body>
        super secret
    </body>
</html>
