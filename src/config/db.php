<?php
// config/db.php - PDO Database Wrapper with Auto-Migration

require_once __DIR__ . '/config.php';

class Database {
    private static ?PDO $instance = null;

    public static function getConnection(): PDO {
        if (self::$instance === null) {
            try {
                if (DB_DRIVER === 'mysql') {
                    if (DB_NAME === '' || DB_USER === '' || DB_PASS === '') {
                        throw new PDOException('Configure the private Hostinger database credentials.');
                    }
                    $dsn = "mysql:host=" . DB_HOST . ";port=" . DB_PORT . ";dbname=" . DB_NAME . ";charset=utf8mb4";
                    self::$instance = new PDO($dsn, DB_USER, DB_PASS, [
                        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                        PDO::ATTR_EMULATE_PREPARES => false,
                    ]);
                } else {
                    $dir = dirname(DB_SQLITE_PATH);
                    if (!is_dir($dir)) {
                        mkdir($dir, 0755, true);
                    }
                    self::$instance = new PDO("sqlite:" . DB_SQLITE_PATH, null, null, [
                        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    ]);
                    self::$instance->exec("PRAGMA journal_mode = WAL; PRAGMA busy_timeout=5000;");
                }

                self::ensureTables();

            } catch (PDOException $e) {
                if (PHP_SAPI === 'cli') throw new RuntimeException('Database connection failed.', 0, $e);
                http_response_code(503);
                if (APP_ENV === 'development') {
                    die("Database connection failed: " . htmlspecialchars($e->getMessage()));
                } else {
                    die("Database service temporarily unavailable.");
                }
            }
        }
        return self::$instance;
    }

    private static function ensureTables(): void {
        $db = self::$instance;
        $isSqlite = (DB_DRIVER === 'sqlite');

        // 1. Users Table
        if ($isSqlite) {
            $db->exec("CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'USER',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )");
        } else {
            $db->exec("CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(50) DEFAULT 'USER',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        }

        // 2. Events Table
        if ($isSqlite) {
            $db->exec("CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                slug TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                tag_line TEXT,
                description TEXT,
                prizepool INTEGER DEFAULT 0,
                event_date TEXT,
                last_reg_date TEXT,
                location TEXT,
                img TEXT,
                registration_fees TEXT,
                coordinator_details TEXT,
                status TEXT DEFAULT 'ACTIVE',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )");
        } else {
            $db->exec("CREATE TABLE IF NOT EXISTS events (
                id INT AUTO_INCREMENT PRIMARY KEY,
                slug VARCHAR(100) UNIQUE NOT NULL,
                title VARCHAR(255) NOT NULL,
                tag_line VARCHAR(255),
                description TEXT,
                prizepool INT DEFAULT 0,
                event_date VARCHAR(100),
                last_reg_date VARCHAR(100),
                location VARCHAR(255),
                img VARCHAR(255),
                registration_fees TEXT,
                coordinator_details TEXT,
                status VARCHAR(50) DEFAULT 'ACTIVE',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        }

        // 3. Submissions Table
        if ($isSqlite) {
            $db->exec("CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                phone TEXT NOT NULL,
                email TEXT,
                form_data TEXT,
                payment_proof TEXT,
                status TEXT DEFAULT 'PENDING',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )");
        } else {
            $db->exec("CREATE TABLE IF NOT EXISTS submissions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                event_id INT NOT NULL,
                name VARCHAR(255) NOT NULL,
                phone VARCHAR(50) NOT NULL,
                email VARCHAR(255),
                form_data TEXT,
                payment_proof VARCHAR(255),
                status VARCHAR(50) DEFAULT 'PENDING',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        }

        // 4. Visitors Table
        if ($isSqlite) {
            $db->exec("CREATE TABLE IF NOT EXISTS visitors (
                id INTEGER PRIMARY KEY,
                count INTEGER DEFAULT 0,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )");
        } else {
            $db->exec("CREATE TABLE IF NOT EXISTS visitors (
                id INT PRIMARY KEY,
                count INT DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        }

        // Seed default admin if missing
        $stmt = $db->query("SELECT COUNT(*) FROM users");
        if ((int)$stmt->fetchColumn() === 0) {
            $hash = password_hash(DEFAULT_ADMIN_PASS, PASSWORD_DEFAULT);
            $ins = $db->prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'ADMIN')");
            $ins->execute([DEFAULT_ADMIN_USER, $hash]);
        }

        // Seed visitor count if missing
        $stmt = $db->query("SELECT COUNT(*) FROM visitors");
        if ((int)$stmt->fetchColumn() === 0) {
            $db->exec("INSERT INTO visitors (id, count) VALUES (1, 0)");
        }

        // Published event details are managed by the CMS; no legacy demonstration events are seeded.
    }
}
