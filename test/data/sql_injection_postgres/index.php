<html>
    <body>
        <a href="/vuln.php?id=1">Article 1</a>
        <a href="/not_vuln.php?id=2">Article 2</a>
        <a href="/index.php?id=3">Article 3</a>
        <a href="/vuln.php">select * from table</a>
        <a href="/not_vuln.php?id=5">Article 5</a>
        to jest z php postgres
        <?php
            error_reporting(-1);
            $conn = pg_connect("host=postgres-test user=postgres password=postgres");

            $sql = "
                SELECT id, content FROM (
                    SELECT '1' AS id, 'content 1' AS content UNION
                    SELECT '2' AS id, 'content 2' AS content UNION
                    SELECT '3' AS id, 'content 3' AS content UNION
                    SELECT '4' AS id, 'content 4' AS content) t WHERE id = '" . $_GET['id'] . "'";
            $result = pg_query($sql);
            while($row = pg_fetch_array($result, null, PGSQL_ASSOC)) {
                echo $row["content"];
            }

            pg_free_result($result);
            pg_close($conn);
        ?>
    </body>
</html>
