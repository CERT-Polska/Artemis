<html>
    <body>
        to jest z php
        <?php
            error_reporting(-1);
            $conn = new mysqli("mysql-test", "root", "root", "information_schema");

            $sql = "
                SELECT id, content FROM table1";
            $result = $conn->query($sql);


            while($row = $result->fetch_assoc()) {
                echo $row["content"];
            }
            $conn->close();
        ?>
    </body>
</html>
