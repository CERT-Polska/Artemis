<?php
// Intentionally vulnerable test fixture: user input is passed straight into a shell,
// so shell metacharacters in `host` result in OS command execution.
$host = $_GET['host'] ?? '';
system("echo pinging " . $host);
?>
