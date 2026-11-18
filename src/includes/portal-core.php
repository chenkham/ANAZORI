<?php
declare(strict_types=1);
$portal = require __DIR__ . '/../config.php';
$portal['base_path'] = rtrim($portal['base_path'], '/');
if (session_status() === PHP_SESSION_NONE) {
    session_name('anazori_portal');
    session_start(['cookie_httponly'=>true, 'cookie_secure'=>!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off', 'cookie_samesite'=>'Lax', 'use_strict_mode'=>true, 'cookie_path'=>($portal['base_path'] ?: '') . '/']);
}
$_SESSION['portal_csrf'] ??= bin2hex(random_bytes(32));
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header('Cache-Control: no-store');
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; media-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
function portal_escape(string $value): string { return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function portal_url(string $path = ''): string { global $portal; return $portal['base_path'] . '/' . ltrim($path, '/'); }
function portal_json(array $body, int $status = 200): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    exit;
}
function portal_db(): PDO {
    global $portal;
    static $db;
    if ($db) return $db;
    $dir = $portal['data_dir'];
    if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) throw new RuntimeException('Storage unavailable');
    $root = realpath(__DIR__ . '/..'); $resolved = realpath($dir);
    if (!$resolved || str_starts_with(strtolower(str_replace('\\', '/', $resolved)) . '/', strtolower(str_replace('\\', '/', $root)) . '/')) throw new RuntimeException('Storage must be outside the web root');
    $db = new PDO('sqlite:' . $dir . '/portal.sqlite', null, null, [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]);
    $db->exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;');
    $db->exec('CREATE TABLE IF NOT EXISTS registrations (id TEXT PRIMARY KEY, event TEXT NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL, college TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(event,email)); CREATE TABLE IF NOT EXISTS feedback (id TEXT PRIMARY KEY, message TEXT NOT NULL, created_at TEXT NOT NULL); CREATE TABLE IF NOT EXISTS rate_limits (key TEXT PRIMARY KEY, attempts INTEGER NOT NULL, expires INTEGER NOT NULL)');
    return $db;
}
// IP-backed, transactionally updated limits survive cookie resets and concurrent requests.
function portal_rate_limit(PDO $db, string $action, int $limit, int $window): void {
    $key = hash('sha256', $action . ':' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    $now = time();
    $db->exec('BEGIN IMMEDIATE');
    try {
        $db->prepare('DELETE FROM rate_limits WHERE expires <= ?')->execute([$now]);
        $q = $db->prepare('SELECT attempts, expires FROM rate_limits WHERE key = ?'); $q->execute([$key]); $row = $q->fetch();
        $count = ($row['attempts'] ?? 0) + 1; $expires = $row['expires'] ?? ($now + $window);
        $db->prepare('INSERT INTO rate_limits(key,attempts,expires) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET attempts=excluded.attempts')->execute([$key,$count,$expires]);
        $db->exec('COMMIT');
    } catch (Throwable $error) { $db->exec('ROLLBACK'); throw $error; }
    header('X-RateLimit-Limit: ' . $limit); header('X-RateLimit-Remaining: ' . max(0,$limit-$count)); header('X-RateLimit-Reset: ' . $expires);
    if ($count > $limit) { header('Retry-After: ' . max(1,$expires-$now)); portal_json(['success'=>false,'error'=>'Please wait a few minutes before trying again.'],429); }
}
function portal_input(): array {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { header('Allow: POST'); portal_json(['success'=>false,'error'=>'Use POST for this endpoint.'],405); }
    if (strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0])) !== 'application/json') portal_json(['success'=>false,'error'=>'Send application/json.'],415);
    $raw = file_get_contents('php://input', false, null, 0, 16385);
    if (strlen($raw) > 16384) portal_json(['success'=>false,'error'=>'Request is too large.'],413);
    try { $data = json_decode($raw, true, 16, JSON_THROW_ON_ERROR); } catch (JsonException) { portal_json(['success'=>false,'error'=>'Invalid JSON.'],400); }
    if (!is_array($data) || array_is_list($data)) portal_json(['success'=>false,'error'=>'Expected a JSON object.'],400);
    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!is_string($csrf) || !hash_equals($_SESSION['portal_csrf'], $csrf)) portal_json(['success'=>false,'error'=>'Your session expired. Refresh the page and try again.'],403);
    return $data;
}
function portal_text(array $data, string $key, int $min, int $max): string {
    $value = $data[$key] ?? null;
    if (!is_string($value)) portal_json(['success'=>false,'error'=>'Please provide a valid ' . $key . '.'],422);
    $value = trim($value);
    if (mb_strlen($value) < $min || mb_strlen($value) > $max || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F<>]/u', $value)) portal_json(['success'=>false,'error'=>'Please check the ' . $key . ' field.'],422);
    return $value;
}
