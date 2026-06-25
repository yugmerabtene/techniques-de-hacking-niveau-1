<?php
/**
 * =====================================================================
 * index.php — Application vulnérable PROTÉGÉE derrière un WAF
 * =====================================================================
 * Cette application contient une injection SQL volontaire dans le
 * paramètre GET 'id', mais elle est placée derrière un WAF ModSecurity
 * qui bloque les payloads standards.
 *
 * Objectif du lab : contourner les règles ModSecurity (bypass WAF)
 * pour réussir à injecter du SQL malgré le filtrage.
 *
 * Note : la connexion MySQL vers "db" est intentionnellement absente —
 * la page affiche la requête construite mais ne l'exécute pas si MySQL
 * est indisponible. L'exercice porte sur le bypass du WAF.
 * =====================================================================
 */

// En-tête HTTP avec charset UTF-8
header("Content-Type: text/html; charset=utf-8");
echo "<h1>Product Search</h1>";

// Tentative de connexion à la base MySQL "db" (hôte externe)
// @ supprime les warnings si la connexion échoue (lab autonome)
$con = @mysqli_connect("db", "root", "rootpass", "testdb");

// Si la base de données n'est PAS disponible, on affiche uniquement
// la requête SQL construite — cela suffit pour le lab de bypass WAF
if (!$con) {
    // Récupération du paramètre 'id' sans validation
    $id = $_GET['id'] ?? '';

    // Formulaire de recherche de produit
    echo '<form method="GET">';
    echo '<input type="text" name="id" placeholder="Product ID">';
    echo '<input type="submit" value="Search">';
    echo '</form>';

    // Si un ID est fourni, construction de la requête SQL
    if ($id) {
        // Affichage de l'ID recherché (échappé HTML)
        echo "<p>Searching for product: <b>" . htmlspecialchars($id) . "</b></p>";

        // VULNÉRABLE : concaténation directe de $id dans la requête SQL
        // Sans le WAF, une injection standard comme 1 OR 1=1 fonctionnerait.
        // Avec ModSecurity CRS actif, ces payloads sont bloqués (403 Forbidden).
        // Il faut trouver des variantes/encodages que le WAF ne détecte pas.
        $query = "SELECT * FROM products WHERE id = " . $id;

        // Affichage de la requête — permet de voir la payload après bypass
        echo "<p>Query: <code>" . htmlspecialchars($query) . "</code></p>";
    }
}
?>
