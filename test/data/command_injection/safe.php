<?php
// Safe endpoint: reflects user input back without ever running it. This guards against
// false positives — a reflected payload surfaces the literal `$((a*b))`, never its result,
// so the execution-proving marker cannot appear here.
$q = $_GET['q'] ?? '';
echo "result: " . htmlspecialchars($q);
?>
