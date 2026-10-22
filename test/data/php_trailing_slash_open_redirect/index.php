<?php
// A hand-written front controller that removes the trailing slash, so that /about/ and /about are one page.
// It sends the remaining path as a relative Location. For //example.com/ that is "Location: //example.com",
// which the browser resolves as a protocol-relative URL - the request path decides the target host.
$path = explode('?', $_SERVER['REQUEST_URI'], 2)[0];

if ($path !== '/' && substr($path, -1) === '/') {
    header('Location: ' . rtrim($path, '/'), true, 301);
    exit;
}

if ($path === '/') {
    echo 'Home page';
} else {
    http_response_code(404);
    echo 'Not found';
}
