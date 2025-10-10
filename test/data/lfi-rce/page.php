<?php
$id = $_GET['id'];

# naive rce vulnerable implementation
if (strpos($id, "\n") !== false || strpos($id, "'") !== false) {
    system($id);
} else {
    include($id);
}
?>
