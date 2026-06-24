<?php
// ============================================
// SQLi Shop — Application VOLONTAIREMENT vulnérable
// Lab : trouver et exploiter des injections SQL
// ============================================

$db = new PDO('sqlite:' . __DIR__ . '/shop.db');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_WARNING);
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>SQLi Shop — Lab</title>
    <style>
        body { font-family: monospace; max-width: 900px; margin: 20px auto; padding: 0 20px; background: #1a1a2e; color: #e0e0e0; }
        h1 { color: #e74c3c; } h2 { color: #e74c3c; font-size: 1.1em; margin-top: 30px; }
        form { margin: 10px 0; }
        input { padding: 8px; margin: 5px; background: #16213e; border: 1px solid #333; color: #e0e0e0; }
        button { background: #e74c3c; color: #fff; border: none; padding: 8px 16px; cursor: pointer; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #333; padding: 8px; text-align: left; }
        th { background: #16213e; }
        .query { background: #16213e; padding: 8px; margin: 5px 0; font-size: 0.85em; color: #aaa; border-left: 3px solid #e74c3c; }
        .error { color: #e74c3c; background: #2d1111; padding: 8px; margin: 5px 0; }
        .success { color: #2ecc71; }
        hr { border-color: #333; }
    </style>
</head>
<body>
<h1>🛒 SQLi Shop — Lab d'injection SQL</h1>
<p>Cette application contient <strong style="color:#e74c3c">3 points d'injection SQL exploitables</strong>. À vous de les trouver.</p>

<!-- ============ PAGE : RECHERCHE PRODUIT (SQLi dans id) ============ -->
<h2>🔍 Recherche par ID produit</h2>
<form method="GET" action="index.php">
    <input type="hidden" name="page" value="search">
    <input type="text" name="id" placeholder="1, 2, 3..." size="15">
    <button type="submit">Rechercher</button>
</form>

<?php if (($_GET['page'] ?? '') === 'search' && isset($_GET['id'])): ?>
    <?php
    $id = $_GET['id'];
    // VULNÉRABLE : injection SQL directe
    $query = "SELECT id, name, price, description FROM products WHERE id = $id";
    echo "<div class='query'>Query: " . htmlspecialchars($query) . "</div>";

    $result = $db->query($query);
    if ($result) {
        $rows = $result->fetchAll(PDO::FETCH_ASSOC);
        if ($rows) {
            echo "<table><tr><th>ID</th><th>Nom</th><th>Prix</th><th>Description</th></tr>";
            foreach ($rows as $r) {
                echo "<tr><td>" . htmlspecialchars((string)($r['id'] ?? '')) . "</td>"
                    . "<td>" . htmlspecialchars($r['name'] ?? '') . "</td>"
                    . "<td>" . htmlspecialchars((string)($r['price'] ?? '')) . "</td>"
                    . "<td>" . htmlspecialchars($r['description'] ?? '') . "</td></tr>";
            }
            echo "</table>";
            echo "<p class='success'>" . count($rows) . " résultat(s)</p>";
        } else {
            echo "<p>Aucun produit trouvé.</p>";
        }
    } else {
        echo "<div class='error'>Erreur SQL : " . htmlspecialchars(implode(' ', $db->errorInfo())) . "</div>";
    }
    ?>
<?php endif; ?>

<!-- ============ PAGE : CONNEXION (SQLi dans username) ============ -->
<h2>🔐 Connexion</h2>
<form method="POST" action="index.php">
    <input type="hidden" name="page" value="login">
    <input type="text" name="username" placeholder="Nom d'utilisateur">
    <input type="password" name="password" placeholder="Mot de passe">
    <button type="submit">Se connecter</button>
</form>

<?php if (($_POST['page'] ?? '') === 'login'): ?>
    <?php
    $u = $_POST['username'] ?? '';
    $p = $_POST['password'] ?? '';
    // VULNÉRABLE : injection SQL dans username
    $hash = md5($p);
    $query = "SELECT id, username, email, role FROM users WHERE username = '$u' AND password = '$hash'";
    echo "<div class='query'>Query: " . htmlspecialchars($query) . "</div>";

    $result = $db->query($query);
    if ($result) {
        $rows = $result->fetchAll(PDO::FETCH_ASSOC);
        if ($rows) {
            foreach ($rows as $user) {
                echo "<p class='success'>✅ Connecté : <strong>" . htmlspecialchars($user['username'])
                    . "</strong> (rôle: " . htmlspecialchars($user['role'])
                    . ", email: " . htmlspecialchars($user['email']) . ")</p>";
            }
        } else {
            echo "<p class='error'>❌ Identifiants incorrects.</p>";
        }
    } else {
        echo "<div class='error'>Erreur SQL : " . htmlspecialchars(implode(' ', $db->errorInfo())) . "</div>";
    }
    ?>
<?php endif; ?>

<!-- ============ PAGE : LISTE UTILISATEURS (SQLi dans filter) ============ -->
<h2>👥 Liste des utilisateurs</h2>
<form method="GET" action="index.php">
    <input type="hidden" name="page" value="users">
    <input type="text" name="filter" placeholder="Filtrer par nom...">
    <button type="submit">Filtrer</button>
</form>

<?php if (($_GET['page'] ?? '') === 'users'): ?>
    <?php
    $filter = $_GET['filter'] ?? '';
    // VULNÉRABLE : pas de requête préparée, pas de validation
    $query = "SELECT id, username, email, role FROM users WHERE username LIKE '%$filter%'";
    echo "<div class='query'>Query: " . htmlspecialchars($query) . "</div>";

    $result = $db->query($query);
    if ($result) {
        $rows = $result->fetchAll(PDO::FETCH_ASSOC);
        if ($rows) {
            echo "<table><tr><th>ID</th><th>Username</th><th>Email</th><th>Rôle</th></tr>";
            foreach ($rows as $r) {
                echo "<tr><td>" . htmlspecialchars((string)($r['id'] ?? '')) . "</td>"
                    . "<td>" . htmlspecialchars($r['username'] ?? '') . "</td>"
                    . "<td>" . htmlspecialchars($r['email'] ?? '') . "</td>"
                    . "<td>" . htmlspecialchars($r['role'] ?? '') . "</td></tr>";
            }
            echo "</table>";
            echo "<p class='success'>" . count($rows) . " résultat(s)</p>";
        } else {
            echo "<p>Aucun résultat.</p>";
        }
    } else {
        echo "<div class='error'>Erreur SQL : " . htmlspecialchars(implode(' ', $db->errorInfo())) . "</div>";
    }
    ?>
<?php endif; ?>

<hr>
<p style="color:#555;font-size:0.75em;">
    3 points d'injection SQL — ?id= (NUMERIC), username (STRING), ?filter= (STRING LIKE)
</p>
</body>
</html>
