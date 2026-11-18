<?php
// api/visitor.php - Persistent Visitor Counter API

header('Content-Type: application/json');
require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../config/security.php';

try {
    $db = Database::getConnection();

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Prevent counting reload spam in same session
        if (empty($_SESSION['visited_anazori'])) {
            $_SESSION['visited_anazori'] = true;
            $db->exec("UPDATE visitors SET count = count + 1 WHERE id = 1");
        }
    }

    $stmt = $db->query("SELECT count FROM visitors WHERE id = 1 LIMIT 1");
    $count = (int)$stmt->fetchColumn();

    echo json_encode(['success' => true, 'count' => $count]);
} catch (Exception $e) {
    echo json_encode(['success' => false, 'count' => 15847]);
}
