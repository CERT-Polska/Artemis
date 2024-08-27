<html>
    <body>
        <?php
            error_reporting(-1);

            $conn = new mysqli("sql-injection-test-mysql", "root", "root", "information_schema");

            $sql = "
            SELECT id, content FROM table1";
            $result = $conn->query($sql);

            $conn->close();
        ?>
    </body>
</html>
