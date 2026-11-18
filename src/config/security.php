<?php
// Shared request headers, CSRF and rate limits.

require_once __DIR__ . '/config.php';
require_once __DIR__.'/../includes/upload-security95.php';

// Security Headers
function set_security_headers(): void {
    if (!headers_sent()) {
        header("X-Content-Type-Options: nosniff");
        header("X-Frame-Options: SAMEORIGIN");
        header("Content-Security-Policy: object-src 'none'; base-uri 'self'; frame-ancestors 'self'");
        header('Permissions-Policy: camera=(self), microphone=(), geolocation=(), usb=()');
        if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') header('Strict-Transport-Security: max-age=31536000');
        header("Referrer-Policy: strict-origin-when-cross-origin");
    }
}

// XSS Prevention: HTML-escape any output
function e(?string $string): string {
    return htmlspecialchars($string ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

// CSRF Token Management
function csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrf_field(): string {
    return '<input type="hidden" name="csrf_token" value="' . e(csrf_token()) . '">';
}

function csrf_input(): string {
    return csrf_field();
}

function is_admin(): bool {
    return !empty($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true;
}

function csrf_verify(?string $token = null): bool {
    $token = $token ?? $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!is_string($token) || !is_string($_SESSION['csrf_token'] ?? null) || $token === '' || ($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '') === 'cross-site') {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

// Rate Limiting (in-session basic protection against brute-force)
function rate_limit_check(string $action, int $maxAttempts = 5, int $decaySeconds = 60): bool {
    $now = time();
    $key = 'rate_' . $action;

    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = ['attempts' => 1, 'first_attempt' => $now];
        return true;
    }

    if ($now - $_SESSION[$key]['first_attempt'] > $decaySeconds) {
        $_SESSION[$key] = ['attempts' => 1, 'first_attempt' => $now];
        return true;
    }

    if ($_SESSION[$key]['attempts'] >= $maxAttempts) {
        return false;
    }

    $_SESSION[$key]['attempts']++;
    return true;
}

// Secure Image File Upload Validator
function handle_secure_upload(array $file): array {
    if(($file['error']??null)===UPLOAD_ERR_NO_FILE)return ['success'=>true,'filename'=>null];
    try {
        if(!rate_limit_check('legacy_upload',10,900))throw new RuntimeException('Too many uploads. Please wait.');
        $info=az_validate_upload95($file,['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp'],MAX_UPLOAD_SIZE);
        if(!is_dir(UPLOAD_DIR)&&!mkdir(UPLOAD_DIR,0755,true))throw new RuntimeException('Upload storage unavailable.');
        $name=bin2hex(random_bytes(24)).'.'.$info['extension'];
        if(!move_uploaded_file($file['tmp_name'],UPLOAD_DIR.$name))throw new RuntimeException('The upload could not be saved.');
        return ['success'=>true,'filename'=>$name];
    } catch(Throwable $e) {return ['success'=>false,'error'=>$e->getMessage()];}
}
