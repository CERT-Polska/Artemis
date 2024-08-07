<html>
    <body>
        <a href="/vuln.php?id=1">Article 1</a>
        <a href="/not_vuln.php?id=2">Article 2</a>
        <a href="/index.php?id=3">Article 3</a>
        <a href="/vuln.php">select * from table</a>
        <a href="/not_vuln.php?id=5">Article 5</a>
        to jest z php mysql
        <?php
            error_reporting(-1);
            $conn = new mysqli("mysql-test", "root", "root", "information_schema");

             $sql = "
                SELECT id, content FROM (
                    SELECT '1' AS id, 'content 1' AS content UNION
                    SELECT '2' AS id, 'content 2' AS content UNION
                    SELECT '3' AS id, 'content 3' AS content UNION
                    SELECT '4' AS id, 'content 4' AS content) t WHERE id = '" . $_GET['id'] . "'";
             $result = $conn->query($sql);
             if ($result === false) {
                 echo ("Query failed: " . $conn->error);
             }
            while($row = $result->fetch_assoc()) {
                echo $row["content"];
            }
            $conn->close();
        ?>
    </body>
</html>
