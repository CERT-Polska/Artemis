<html>
    <body>
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
