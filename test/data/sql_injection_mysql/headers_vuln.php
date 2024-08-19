<html>
    <body>
        <a href="/vuln.php?id=1">Article 1</a>
        <a href="/not_vuln.php?id=2">Article 2</a>
        <a href="/index.php?id=3">Article 3</a>
        <a href="/vuln.php">select * from table</a>
        <a href="/not_vuln.php?id=5">Article 5</a>
        <a href="/headers_vuln.php">Article 5</a>
        <?php
            error_reporting(-1);
            $conn = new mysqli("sql-injection-test-mysql", "root", "root", "information_schema");
            $headers = getallheaders();
            $user_agent = $headers["User-Agent"];

            $sql = "
            SELECT id FROM (SELECT '1' AS id) t WHERE id = '" . $user_agent . "'";
            $result = $conn->query($sql);
            if ($result === false) {
                echo ("Query failed: " . $conn->error);
            }

            $conn->close();

        ?>
    </body>
</html>
