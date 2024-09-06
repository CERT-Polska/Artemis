<?php
            error_reporting(-1);
            $conn = new mysqli("sql-injection-test-mysql", "root", "root", "information_schema");

            $sql = "
            SELECT id FROM (SELECT '1' AS id) t WHERE id = '" . $_GET['id'] . "'";
            $result = $conn->query($sql);
            if ($result === false) {
                echo ("Query failed: " . $conn->error);
            }
            $conn->close();
        ?>
