<html>
    <body>
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
