<html>
    <body>
        to jest z xss
        <?php
            error_reporting(-1);

//             $conn = pg_connect("host=test-service-with-sql-injection-postgres-db user=root password=root");
            $conn = pg_connect("host=postgres user=postgres password=postgres");
//             $conn = pg_connect("postgresql://postgres:postgres@postgres/artemis");


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
