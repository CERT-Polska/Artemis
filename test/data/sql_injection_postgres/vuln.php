<html>
    <body>
        to jest z php
        <?php
            error_reporting(-1);

            $conn = pg_connect("host=sql-injection-test-postgres user=postgres password=postgres");

            $sql = "
                SELECT id, content FROM table1";
            $result = pg_query($sql);
            while($row = pg_fetch_array($result, null, PGSQL_ASSOC)) {
                echo $row["content"];
            }

            pg_free_result($result);
            pg_close($conn);
        ?>
    </body>
</html>
