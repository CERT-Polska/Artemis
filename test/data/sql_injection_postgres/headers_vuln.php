<html>
    <body>
        <a href="/vuln.php?id=1">Article 1</a>
        <a href="/not_vuln.php?id=2">Article 2</a>
        <a href="/index.php?id=3">Article 3</a>
        <a href="/vuln.php">select * from table</a>
        <a href="/not_vuln.php?id=5">Article 5</a>
        <a href="/headers_vuln.php">Article 6</a>
        <?php
            error_reporting(-1);
            $conn = pg_connect("host=sql-injection-test-postgres user=postgres password=postgres");
            $headers = getallheaders();
            $user_agent = $headers["User-Agent"];

            $sql = "
                SELECT id FROM (SELECT '1' AS id) t WHERE id = '" . $user_agent . "'";

            $result = pg_query($sql);

            pg_close($conn);
        ?>
    </body>
</html>
