<?php
declare(strict_types=1);

/** Event ownership is separate from module permissions. Every staff account starts with no events. */
function st_install_access(PDO $db): void {
    if ($db->query("SELECT value FROM cms_settings WHERE setting_key='studio_access_schema'")->fetchColumn() === '2') return;
    $sqlite = $db->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite';
    $id = $sqlite ? 'INTEGER PRIMARY KEY AUTOINCREMENT' : 'INT AUTO_INCREMENT PRIMARY KEY';
    $text = $sqlite ? 'TEXT' : 'MEDIUMTEXT';
    $columns = $sqlite
        ? array_column($db->query('PRAGMA table_info(users)')->fetchAll(), 'name')
        : array_column($db->query('SHOW COLUMNS FROM users')->fetchAll(), 'Field');
    if (!in_array('event_scope', $columns, true)) {
        try {
            $db->exec("ALTER TABLE users ADD COLUMN event_scope VARCHAR(20) NOT NULL DEFAULT 'assigned'");
        } catch (PDOException $error) {
            // Two first requests may observe the old schema together; accept only an already-added column.
            $current = $sqlite
                ? array_column($db->query('PRAGMA table_info(users)')->fetchAll(), 'name')
                : array_column($db->query('SHOW COLUMNS FROM users')->fetchAll(), 'Field');
            if (!in_array('event_scope', $current, true)) throw $error;
        }
    }
    $db->exec('CREATE TABLE IF NOT EXISTS st_event_assignments (
        user_id INT NOT NULL,
        event_id INT NOT NULL,
        assigned_by INT NOT NULL,
        assigned_at VARCHAR(40) NOT NULL,
        PRIMARY KEY (user_id, event_id)
    )');
    $db->exec("CREATE TABLE IF NOT EXISTS st_event_activity (
        id $id,
        event_id INT NOT NULL,
        user_id INT NOT NULL,
        username VARCHAR(100) NOT NULL,
        action VARCHAR(100) NOT NULL,
        detail $text NOT NULL,
        created_at VARCHAR(40) NOT NULL
    )");
    foreach (['st_event_assignments_event' => 'st_event_assignments (event_id,user_id)',
              'st_orders_event_participant' => 'az_orders (event_id,participant_id,id)',
              'st_event_activity_event' => 'st_event_activity (event_id,id)'] as $name => $definition) {
        try {
            $db->exec('CREATE INDEX '.($sqlite ? 'IF NOT EXISTS ' : '').$name.' ON '.$definition);
        } catch (PDOException $error) {
            if ((int)($error->errorInfo[1] ?? 0) !== 1061) throw $error;
        }
    }
    $marker = $db->prepare('SELECT value FROM cms_settings WHERE setting_key=?');
    $marker->execute(['studio_access_schema']);
    if ($marker->fetchColumn() === false) {
        try {
            $db->prepare('INSERT INTO cms_settings(setting_key,value) VALUES(?,?)')->execute(['studio_access_schema','2']);
        } catch (PDOException $error) {
            $marker->execute(['studio_access_schema']);
            if ($marker->fetchColumn() === false) throw $error;
            $db->prepare('UPDATE cms_settings SET value=? WHERE setting_key=?')->execute(['2','studio_access_schema']);
        }
    } else {
        $db->prepare('UPDATE cms_settings SET value=? WHERE setting_key=?')->execute(['2','studio_access_schema']);
    }
}

/** Never grant scope from a role or event_scope supplied by a caller or an old session. */
function st_access_staff(array $user): ?array {
    $id = (int)($user['id'] ?? 0);
    if ($id < 1) return null;
    $query = cms_db()->prepare('SELECT id,username,email,role,active,session_version,event_scope,permissions,modules,display_name,staff_title,must_change_password FROM users WHERE id=?');
    $query->execute([$id]);
    $staff = $query->fetch();
    if (!$staff || !(int)$staff['active'] || !in_array($staff['role'], ['SUPERADMIN','ADMIN','FACULTY','COORDINATOR','EDITOR','VOLUNTEER'], true)) return null;
    if (isset($user['session_version']) && (int)$user['session_version'] !== (int)$staff['session_version']) return null;
    if ($staff['role'] === 'SUPERADMIN' && !az_is_super($staff)) return null;
    return $staff;
}

/** Recheck account and session after obtaining the write lock, before checking mutation permissions. */
function st_refresh_user(array $user): array {
    $staff = st_access_staff($user);
    if (!$staff) throw new RuntimeException('Your staff access changed. Sign in again to continue.');
    return $staff;
}

/** null = all events; [] = no events; otherwise canonical cms_content event IDs. */
function st_event_ids(array $user): ?array {
    $staff = st_access_staff($user);
    if (!$staff) return [];
    if (az_is_super($staff) || $staff['event_scope'] === 'all') return null;
    $query = cms_db()->prepare("SELECT a.event_id FROM st_event_assignments a JOIN cms_content c ON c.id=a.event_id AND c.type='event' WHERE a.user_id=? ORDER BY a.event_id");
    $query->execute([(int)$staff['id']]);
    return array_map('intval', $query->fetchAll(PDO::FETCH_COLUMN));
}

function st_has_global_access(array $user): bool {
    return st_event_ids($user) === null;
}

function st_can_event(array $user, int $eventId): bool {
    if ($eventId < 1) return false;
    $ids = st_event_ids($user);
    if ($ids !== null) return in_array($eventId, $ids, true);
    $query = cms_db()->prepare("SELECT id FROM cms_content WHERE id=? AND type='event'");
    $query->execute([$eventId]);
    return $query->fetchColumn() !== false;
}

function st_require_event(array $user, int $eventId): void {
    if (!st_can_event($user, $eventId)) throw new RuntimeException('This event is outside your assigned studio access.');
}

/** Column names must be trusted code identifiers; values always use positional parameters. */
function st_scope_column(string $column): string {
    if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?$/D', $column)) {
        throw new InvalidArgumentException('Invalid event scope column.');
    }
    return $column;
}

function st_scope_sql(array $user, string $column): array {
    $column = st_scope_column($column);
    $ids = st_event_ids($user);
    if ($ids === null) return ['sql' => '1=1', 'params' => []];
    if (!$ids) return ['sql' => '1=0', 'params' => []];
    return ['sql' => $column.' IN ('.implode(',', array_fill(0, count($ids), '?')).')', 'params' => $ids];
}

/** Includes drafts and archived events because authorised staff need their operational history. */
function st_scoped_events(array $user): array {
    $scope = st_scope_sql($user, 'c.id');
    $query = cms_db()->prepare("SELECT c.* FROM cms_content c WHERE c.type='event' AND (".$scope['sql'].') ORDER BY c.sort_order,c.id');
    $query->execute($scope['params']);
    return array_map('cms_unpack', $query->fetchAll());
}

/** Append only a short server-generated summary, never credentials, pass tokens or gateway payloads. */
function st_event_audit(array $user, int $eventId, string $action, string $detail): void {
    $staff = st_refresh_user($user);
    st_require_event($staff, $eventId);
    if (!preg_match('/^[a-z0-9][a-z0-9_.-]{0,99}$/D', $action) || mb_strlen($detail) > 2000 || str_contains($detail, "\0")) {
        throw new InvalidArgumentException('Use a short valid event activity summary.');
    }
    $detail = preg_replace('/AZ16-[A-F0-9]{14}\.[a-f0-9]{64}/', '[pass token omitted]', $detail);
    cms_db()->prepare('INSERT INTO st_event_activity(event_id,user_id,username,action,detail,created_at) VALUES(?,?,?,?,?,?)')->execute([$eventId,(int)$staff['id'],$staff['username'],$action,$detail,gmdate('c')]);
}

function st_event_activity_rows(array $user, int $eventId = 0, int $limit = 50, int $offset = 0): array {
    $scope = st_scope_sql($user, 'a.event_id');
    $params = $scope['params'];
    $where = '('.$scope['sql'].')';
    if ($eventId > 0) {
        $where .= ' AND a.event_id=?';
        $params[] = $eventId;
    }
    $limit = max(1, min(200, $limit));
    $offset = max(0, $offset);
    $query = cms_db()->prepare("SELECT a.*,c.title event_title FROM st_event_activity a LEFT JOIN cms_content c ON c.id=a.event_id AND c.type='event' WHERE ".$where.' ORDER BY a.id DESC LIMIT '.$limit.' OFFSET '.$offset);
    $query->execute($params);
    return $query->fetchAll();
}

/** Legacy events and CMS events have independent IDs. Their immutable slugs establish the mapping. */
function st_legacy_scope_sql(array $user, string $legacyColumn): array {
    $legacyColumn = st_scope_column($legacyColumn);
    $scope = st_scope_sql($user, 'st_access_event.id');
    if ($scope['sql'] === '1=1' || $scope['sql'] === '1=0') return $scope;
    return ['sql' => $legacyColumn." IN (SELECT st_access_legacy.id FROM events st_access_legacy JOIN cms_content st_access_event ON st_access_event.type='event' AND st_access_event.slug=st_access_legacy.slug WHERE ".$scope['sql'].')', 'params' => $scope['params']];
}

function st_legacy_cms_id(int $legacyEventId): ?int {
    $query = cms_db()->prepare("SELECT c.id FROM cms_content c JOIN events e ON e.slug=c.slug WHERE c.type='event' AND e.id=?");
    $query->execute([$legacyEventId]);
    $id = $query->fetchColumn();
    return $id === false ? null : (int)$id;
}

function st_can_legacy_event(array $user, int $legacyEventId): bool {
    if ($legacyEventId < 1) return false;
    $scope = st_legacy_scope_sql($user, 'e.id');
    $query = cms_db()->prepare('SELECT e.id FROM events e WHERE e.id=? AND ('.$scope['sql'].')');
    $query->execute(array_merge([$legacyEventId], $scope['params']));
    return $query->fetchColumn() !== false;
}

function st_require_legacy_event(array $user, int $legacyEventId): void {
    if (!st_can_legacy_event($user, $legacyEventId)) throw new RuntimeException('This event is outside your assigned studio access.');
}

/** Fetch authoritative rows with the scope in the same SQL statement; do not trust posted event IDs. */
function st_require_order(array $user, int $orderId): array {
    $scope = st_scope_sql($user, 'o.event_id');
    $query = cms_db()->prepare('SELECT o.* FROM az_orders o WHERE o.id=? AND ('.$scope['sql'].')');
    $query->execute(array_merge([$orderId], $scope['params']));
    $order = $query->fetch();
    if (!$order) throw new RuntimeException('This order is unavailable in your assigned events.');
    return $order;
}

/** The parent order determines ticket ownership, including when a redundant ticket event_id is wrong. */
function st_require_ticket(array $user, int $ticketId): array {
    $scope = st_scope_sql($user, 'o.event_id');
    $query = cms_db()->prepare('SELECT t.*,o.event_id order_event_id,o.snapshot,o.environment,o.state order_state FROM az_tickets t JOIN az_orders o ON o.id=t.order_id WHERE t.id=? AND ('.$scope['sql'].')');
    $query->execute(array_merge([$ticketId], $scope['params']));
    $ticket = $query->fetch();
    if (!$ticket) throw new RuntimeException('This ticket is unavailable in your assigned events.');
    return $ticket;
}

/** Coordinators can see only people registered in their events; participant accounts remain shared. */
function st_participant_scope_sql(array $user, string $participantColumn): array {
    $participantColumn = st_scope_column($participantColumn);
    $scope = st_scope_sql($user, 'st_access_order.event_id');
    if ($scope['sql'] === '1=1' || $scope['sql'] === '1=0') return $scope;
    return ['sql' => 'EXISTS (SELECT 1 FROM az_orders st_access_order WHERE st_access_order.participant_id='.$participantColumn.' AND '.$scope['sql'].')', 'params' => $scope['params']];
}

function st_require_participant(array $user, int $participantId, bool $mutatesAccount = false): array {
    if ($mutatesAccount && !st_has_global_access($user)) throw new RuntimeException('Shared participant account changes require festival-wide access. Manage passes in your event instead.');
    $scope = st_participant_scope_sql($user, 'p.id');
    $query = cms_db()->prepare('SELECT p.id,p.name,p.email,p.email_verified,p.active,p.created_at FROM az_participants p WHERE p.id=? AND ('.$scope['sql'].')');
    $query->execute(array_merge([$participantId], $scope['params']));
    $participant = $query->fetch();
    if (!$participant) throw new RuntimeException('This participant is unavailable in your assigned events.');
    return $participant;
}

/** Master-only assignment editor can show inactive staff, whose effective access remains empty. */
function st_staff_assignment_state(array $actor, int $targetUserId): array {
    $staff = st_access_staff($actor);
    if (!$staff || !az_is_super($staff)) throw new RuntimeException('Only the master Super Admin can manage event assignments.');
    $query = cms_db()->prepare('SELECT event_scope FROM users WHERE id=?');
    $query->execute([$targetUserId]);
    $scope = $query->fetchColumn();
    if ($scope === false) throw new RuntimeException('Staff account not found.');
    $query = cms_db()->prepare("SELECT a.event_id FROM st_event_assignments a JOIN cms_content c ON c.id=a.event_id AND c.type='event' WHERE a.user_id=? ORDER BY a.event_id");
    $query->execute([$targetUserId]);
    return ['event_scope' => $scope === 'all' ? 'all' : 'assigned', 'event_ids' => array_map('intval', $query->fetchAll(PDO::FETCH_COLUMN))];
}

/** Atomically replace assignments, revoke existing sessions and retain who granted the change. */
function st_set_assignments(array $actor, int $targetUserId, array $eventIds, bool $global): void {
    $ids = [];
    if (count($eventIds) > 1000) throw new InvalidArgumentException('Too many event assignments.');
    foreach ($eventIds as $id) {
        if ((!is_int($id) && !(is_string($id) && ctype_digit($id))) || (int)$id < 1 || (int)$id > 2147483647) throw new InvalidArgumentException('Choose valid event assignments.');
        $ids[] = (int)$id;
    }
    $ids = array_values(array_unique($ids));
    sort($ids);
    $db = cms_db();
    $nested = $db->inTransaction();
    $savepoint = 'st_access_'.bin2hex(random_bytes(6));
    if ($nested) $db->exec('SAVEPOINT '.$savepoint); else $db->beginTransaction();
    try {
        az_lock($db);
        $staff = st_access_staff($actor);
        if (!$staff || !az_is_super($staff)) throw new RuntimeException('Only the master Super Admin can manage event assignments.');
        $query = $db->prepare('SELECT id,username,email,role,event_scope FROM users WHERE id=?');
        $query->execute([$targetUserId]);
        $target = $query->fetch();
        if (!$target || !in_array($target['role'], ['ADMIN','FACULTY','COORDINATOR','EDITOR','VOLUNTEER'], true) || az_is_super($target)) throw new RuntimeException('Choose a staff account other than the fixed master account.');
        if ($ids) {
            $query = $db->prepare("SELECT id FROM cms_content WHERE type='event' AND id IN (".implode(',', array_fill(0, count($ids), '?')).')');
            $query->execute($ids);
            $found = array_map('intval', $query->fetchAll(PDO::FETCH_COLUMN));
            sort($found);
            if ($found !== $ids) throw new InvalidArgumentException('One or more assigned events are unavailable.');
        }
        $db->prepare('DELETE FROM st_event_assignments WHERE user_id=?')->execute([$targetUserId]);
        $now = gmdate('c');
        if (!$global) {
            $insert = $db->prepare('INSERT INTO st_event_assignments(user_id,event_id,assigned_by,assigned_at) VALUES(?,?,?,?)');
            foreach ($ids as $eventId) $insert->execute([$targetUserId,$eventId,(int)$staff['id'],$now]);
        }
        $db->prepare('UPDATE users SET event_scope=?,session_version=session_version+1 WHERE id=?')->execute([$global ? 'all' : 'assigned',$targetUserId]);
        cms_audit($staff, 'staff.events', json_encode(['staff_id'=>$targetUserId,'username'=>$target['username'],'scope'=>$global ? 'all' : 'assigned','event_ids'=>$global ? [] : $ids], JSON_THROW_ON_ERROR));
        if ($nested) $db->exec('RELEASE SAVEPOINT '.$savepoint); else $db->commit();
    } catch (Throwable $error) {
        if ($nested && $db->inTransaction()) {
            $db->exec('ROLLBACK TO SAVEPOINT '.$savepoint);
            $db->exec('RELEASE SAVEPOINT '.$savepoint);
        } elseif ($db->inTransaction()) {
            $db->rollBack();
        }
        throw $error;
    }
}
