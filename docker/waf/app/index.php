<?php
// Application vulnérable derrière WAF
header("Content-Type: text/html; charset=utf-8");
echo "<h1>Product Search</h1>";

$con = @mysqli_connect("db", "root", "rootpass", "testdb");
if (!$con) {
    $id = $_GET['id'] ?? '';
    echo '<form method="GET">';
    echo '<input type="text" name="id" placeholder="Product ID">';
    echo '<input type="submit" value="Search">';
    echo '</form>';

    if ($id) {
        echo "<p>Searching for product: <b>" . htmlspecialchars($id) . "</b></p>";
        $query = "SELECT * FROM products WHERE id = " . $id;
        echo "<p>Query: <code>" . htmlspecialchars($query) . "</code></p>";
    }
}
?>
