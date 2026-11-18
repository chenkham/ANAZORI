<?php
// logout.php - Safe Session Termination
require_once __DIR__ . '/includes/cms.php';
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !is_string($_POST['csrf_token'] ?? null) || !csrf_verify($_POST['csrf_token'])) {
    http_response_code(405); header('Allow: POST'); exit('Use the sign-out button in the studio.');
}

if($participant=az_participant())az_auth_event('logout',$_SESSION['participant_method']??'email_password',$participant);
if($staff=cms_user())az_auth_event('logout',$_SESSION['staff_method']??'email_password',$staff,'staff');
az_remember_revoke102();
$_SESSION = [];
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}
session_destroy();

header("Location: /login.php");
exit;
