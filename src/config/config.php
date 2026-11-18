<?php
// config/config.php - Anazori Fest Configuration
require_once __DIR__.'/runtime.php';

if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_secure', !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? '1' : '0');
    ini_set('session.use_only_cookies', 1);
    ini_set('session.cookie_samesite', 'Lax');
    session_start();
}

// Environment: 'development' or 'production'
define('APP_ENV', getenv('ANAZORI_APP_ENV') ?: 'development');
define('APP_NAME', 'ANAZORI 2026');
define('APP_URL', '');

// Database Configuration (Default: SQLite for zero-setup local dev; toggle to MySQL for Hostinger)
// Set database credentials in the hosting environment; local previews use SQLite.
define('DB_DRIVER', getenv('ANAZORI_DB_DRIVER') ?: 'sqlite');

// MySQL Credentials (for Hostinger)
define('DB_HOST', getenv('ANAZORI_DB_HOST') ?: 'localhost');
define('DB_NAME', getenv('ANAZORI_DB_NAME') ?: '');
define('DB_USER', getenv('ANAZORI_DB_USER') ?: '');
define('DB_PASS', getenv('ANAZORI_DB_PASS') ?: '');
define('DB_PORT', getenv('ANAZORI_DB_PORT') ?: '3306');

// SQLite Path
define('DB_SQLITE_PATH', getenv('ANAZORI_DB_PATH') ?: __DIR__ . '/../data/anazori.sqlite');

// Upload settings
define('UPLOAD_DIR', __DIR__ . '/../uploads/proofs/');
define('MAX_UPLOAD_SIZE', 5 * 1024 * 1024); // 5 MB

// Admin default credentials (hashed upon first db init)
define('DEFAULT_ADMIN_USER', 'admin');
// New public installations must never inherit the known local preview password.
$bootstrapPassword=getenv('ANAZORI_BOOTSTRAP_PASSWORD');
if($bootstrapPassword!==false&&strlen($bootstrapPassword)<12)throw new RuntimeException('The bootstrap password must contain at least 12 characters.');
$localPreview=APP_ENV==='development'&&(PHP_SAPI==='cli'||preg_match('/^(localhost|127\.0\.0\.1)(:\d+)?$/',$_SERVER['HTTP_HOST']??''));
define('DEFAULT_ADMIN_PASS', $bootstrapPassword ?: ($localPreview ? 'admin123' : bin2hex(random_bytes(32))));
unset($bootstrapPassword,$localPreview);
