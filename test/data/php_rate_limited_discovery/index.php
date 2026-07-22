<?php
// A target that rate-limits every request, including the GET requests made during
// path discovery. Used to verify the scan aborts cleanly when 429 is hit before
// the brute-force phase even starts.
http_response_code(429);
header('Retry-After: 60');
echo 'Too Many Requests';
