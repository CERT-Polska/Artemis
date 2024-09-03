<html>
    <body>
xss
        <h1>Witaj na stronie!</h1>

        <!-- Formularz do wprowadzenia danych użytkownika -->
        <form method="GET">
            <label for="username">Podaj swoje imię:</label>
            <input type="text" id="username" name="username">
            <input type="submit" value="Wyślij">
        </form>

        <!-- Wyświetlanie wprowadzonego imienia -->
        <p>Witaj, <?php echo $_GET['username']; ?>!</p>
    </body>
</html>
