<html>
    <body>
        <?php
            error_reporting(-1);

            $conn = pg_connect("host=sql-injection-test-postgres user=postgres password=postgres");

            $sql = "
                SELECT id, content FROM table1";
            $result = pg_query($sql);

            pg_close($conn);
        ?>
    </body>
</html>
