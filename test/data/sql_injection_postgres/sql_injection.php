<html>
    <body>
        <?php
            error_reporting(-1);
            $conn = pg_connect("host=sql-injection-test-postgres user=postgres password=postgres");

            $sql = "
                SELECT id FROM (SELECT '1' AS id) t WHERE id = '" . $_GET['id'] . "'";
            $result = pg_query($sql);

            pg_close($conn);
        ?>
    </body>
</html>
