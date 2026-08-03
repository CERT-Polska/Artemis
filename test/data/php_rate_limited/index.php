<?php
// A target that serves the login page normally (GET 200) but rate-limits every
// login attempt (POST 429). Used to verify the scan aborts the whole host on 429.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    http_response_code(429);
    header('Retry-After: 60');
    echo 'Too Many Requests';
    exit();
}
?>

<!DOCTYPE html>
<html>
<body>
    <div class="login-box">
        <h2>Login</h2>
        <form method="POST" action="/index.php">
            <label>Username</label><br>
            <input type="text" name="username" required><br>
            <label>Password</label><br>
            <input type="password" name="password" required><br>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
