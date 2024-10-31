<html>
    <body>
        <h1>Welcome on our site!</h1>

        <!-- User data entry form -->
        <form method="GET">
            <label for="username"> Please enter the username: </label>
            <input type="text" id="username" name="username">
            <label for="Password"> Please enter the password:</label>
            <input type="text" id="password" name="password">
            <input type="submit" value="Send">
        </form>

        <!-- Displaying the entered name and password -->
        <p>Hello!, <?php echo $_GET['username']; ?>!</p>
        <p>This is your password, <?php echo $_GET['password']; ?>!</p>
    </body>
</html>
