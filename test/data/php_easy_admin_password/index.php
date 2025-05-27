<?php
session_start();

$login_error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    if ($username === 'admin' && $password === 'admin') {
        $_SESSION['loggedin'] = true;
        $_SESSION['username'] = $username;
        header('Location: dashboard.php');
        exit();
    } else {
        $login_error = 'Invalid credentials.';
    }
}
?>

<!DOCTYPE html>
<html>
<body>
    <div class="login-box">
        <h2>Login</h2>
        <?php if ($login_error): ?>
            <p class="error"><?= htmlspecialchars($login_error) ?></p>
        <?php endif; ?>
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
