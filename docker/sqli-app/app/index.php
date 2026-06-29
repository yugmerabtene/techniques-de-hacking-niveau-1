<?php
/**
 * =====================================================================
 * index.php — SQLi Shop — Application VOLONTAIREMENT vulnérable
 * =====================================================================
 * Lab complet d'injection SQL avec 3 points d'injection exploitables.
 * Chaque point est documenté pour l'apprentissage :
 *   1. Injection numérique dans ?id=       (UNION-based)
 *   2. Injection chaîne dans username      (bypass d'authentification)
 *   3. Injection chaîne dans ?filter=      (LIKE, blind SQLi)
 *
 * IMPORTANT : Aucune requête préparée n'est utilisée. Les entrées
 * utilisateur sont concaténées directement dans les requêtes SQL.
 * PDO::ERRMODE_WARNING au lieu d'EXCEPTION pour ne pas bloquer
 * l'exploitation.
 * =====================================================================
 */

// Connexion à la base SQLite via PDO — fichier shop.db dans le même répertoire
$db = new PDO('sqlite:' . __DIR__ . '/shop.db');
// ERRMODE_WARNING au lieu d'ERKMODE_EXCEPTION : les erreurs SQL sont
// affichées comme warnings, ce qui permet à l'attaquant de voir
// les messages d'erreur (utile pour l'injection error-based)
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

<!-- ================================================================= -->
<!-- POINT D'INJECTION 1 : Recherche par ID produit                    -->
<!-- Injection NUMÉRIQUE — pas de guillemets autour de $id             -->
<!-- Vecteur : ?page=search&id=1 UNION SELECT ...                      -->
<!-- ================================================================= -->
<h2>🔍 Recherche par ID produit</h2>
<form method="GET" action="index.php">
    <input type="hidden" name="page" value="search">
    <input type="text" name="id" placeholder="1, 2, 3..." size="15">
    <button type="submit">Rechercher</button>
</form>

<?php if (($_GET['page'] ?? '') === 'search' && isset($_GET['id'])): ?>
    <?php
    $id = $_GET['id'];
    // VULNÉRABLE : $id est concaténé directement dans la requête SQL.
    // Aucune validation de type, aucun échappement.
    // Injection numérique : pas besoin de briser des guillemets.
    // Payload exemple : 1 UNION SELECT 1,2,3,4,sqlite_version()
    $query = "SELECT id, name, price, description FROM products WHERE id = $id";
    // Affichage de la requête exécutée — utile pour comprendre et déboguer
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
        // Affichage des erreurs PDO — information leakage utile pour error-based SQLi
        echo "<div class='error'>Erreur SQL : " . htmlspecialchars(implode(' ', $db->errorInfo())) . "</div>";
    }
    ?>
<?php endif; ?>

<!-- ================================================================= -->
<!-- POINT D'INJECTION 2 : Connexion (bypass d'authentification)       -->
<!-- Injection de type STRING — guillemets simples autour de $u        -->
<!-- Le mot de passe est hashé en MD5 (faible) AVANT la requête,       -->
<!-- mais l'injection dans username permet de contourner le WHERE.     -->
<!-- Vecteur : username=admin'-- avec password quelconque               -->
<!-- ================================================================= -->
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
    // VULNÉRABLE : $u concaténé directement dans la requête.
    // Le mot de passe est hashé en MD5 — algorithme faible et non salé.
    // Injection : admin'-- permet de commenter la partie password du WHERE.
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

<!-- ================================================================= -->
<!-- POINT D'INJECTION 3 : Liste des utilisateurs (filtre LIKE)        -->
<!-- Injection de type STRING dans une clause LIKE — blind SQLi idéal  -->
<!-- Vecteur : ?page=users&filter=%' UNION SELECT ...--                 -->
<!-- ================================================================= -->
<h2>👥 Liste des utilisateurs</h2>
<form method="GET" action="index.php">
    <input type="hidden" name="page" value="users">
    <input type="text" name="filter" placeholder="Filtrer par nom...">
    <button type="submit">Filtrer</button>
</form>

<?php if (($_GET['page'] ?? '') === 'users'): ?>
    <?php
    $filter = $_GET['filter'] ?? '';
    // VULNÉRABLE : $filter est injecté dans un LIKE sans requête préparée.
    // Le % autour de $filter est dans la chaîne SQL, pas dans l'entrée.
    // Payload exemple : %' UNION SELECT id,username,password,role FROM users--
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
