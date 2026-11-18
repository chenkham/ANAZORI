<?php
declare(strict_types=1);

// Isolated in-memory SQLite database; no gateway calls, production data or emails.
putenv('ANAZORI_DB_PATH=:memory:');
putenv('ANAZORI_TEST_MODE=1');
require_once __DIR__.'/../src/includes/cms.php';
require_once __DIR__.'/../src/includes/studio-access.php';
$db = cms_db();
st_install_access($db);
$passed = 0;
function access_check(bool $value, string $message): void {
    global $passed;
    if (!$value) throw new RuntimeException('FAIL '.$message);
    ++$passed;
    echo 'PASS '.$message.PHP_EOL;
}
function access_denied(callable $operation, string $message): void {
    try { $operation(); } catch (RuntimeException|InvalidArgumentException $error) { access_check(true, $message); return; }
    access_check(false, $message);
}
function access_user(int $id): array {
    global $db;
    $query = $db->prepare('SELECT * FROM users WHERE id=?');
    $query->execute([$id]);
    return $query->fetch();
}
try {
    $master = $db->query("SELECT * FROM users WHERE role='SUPERADMIN'")->fetch();
    $db->exec("DELETE FROM cms_content WHERE type='event'; DELETE FROM events;");
    $insert = $db->prepare("INSERT INTO cms_content(id,type,slug,title,data,status,created_by,updated_at) VALUES(?,'event',?,?, '{}','PUBLISHED',0,?)");
    foreach ([[101,'access-one','One'],[202,'access-two','Two']] as $event) $insert->execute([...$event,gmdate('c')]);
    $db->prepare("INSERT INTO events(id,slug,title) VALUES(?,?,?)")->execute([9001,'access-one','One']);
    $db->prepare("INSERT INTO events(id,slug,title) VALUES(?,?,?)")->execute([101,'access-two','Two']);
    $db->prepare("INSERT INTO users(username,email,password_hash,role,active,permissions) VALUES(?,?,'irrelevant','COORDINATOR',1,?)")->execute(['access-coordinator','access@example.com',json_encode(['event.view','payments.view','participants.edit'])]);
    $coordinatorId = (int)$db->lastInsertId();
    $coordinator = access_user($coordinatorId);
    access_check(st_event_ids($coordinator) === [], 'Module permissions alone never expose events.');
    access_check(st_event_ids($master) === null, 'Only verified master is global by default.');
    access_check(st_scope_sql($coordinator,'o.event_id')['sql'] === '1=0', 'Empty assignments produce SQL denial.');
    access_denied(fn()=>st_set_assignments($coordinator,$coordinatorId,[101],true), 'Coordinator cannot grant own scope.');
    access_denied(fn()=>st_set_assignments($master,(int)$master['id'],[],true), 'Fixed master cannot be altered by assignment action.');
    $forged = array_replace($coordinator,['role'=>'SUPERADMIN','username'=>ANAZORI_SUPER_EMAIL,'email'=>ANAZORI_SUPER_EMAIL,'event_scope'=>'all']);
    access_check(st_event_ids($forged) === [], 'Posted or stale identity fields cannot forge global authority.');
    st_set_assignments($master,$coordinatorId,['101',101],false);
    access_check(st_event_ids($coordinator) === [], 'Assignment changes revoke the previous session version.');
    $coordinator = access_user($coordinatorId);
    access_check(st_event_ids($coordinator) === [101], 'Explicit assignments are canonical unique CMS IDs.');
    access_check(st_can_event($coordinator,101) && !st_can_event($coordinator,202), 'Event scope denies another event.');
    access_check(array_column(st_scoped_events($coordinator),'id') === [101], 'Scoped content list contains only assigned events.');
    st_event_audit($coordinator,101,'event.save','Updated event schedule.');
    st_event_audit($master,202,'payment.verify','Verified ORDER-TWO with provider.');
    st_event_audit($master,101,'ticket.revoke','Pass '.('AZ16-'.str_repeat('A',14).'.'.str_repeat('a',64)));
    $activities = st_event_activity_rows($coordinator);
    access_check(count($activities) === 2 && !array_diff(array_column($activities,'event_id'), [101]), 'Operational activity list is limited to the assigned event.');
    access_check(str_contains($activities[0]['detail'],'[pass token omitted]'), 'Structured activity never stores a full pass token.');
    access_check(st_event_activity_rows($coordinator,202) === [], 'Another event activity filter cannot bypass assignments.');
    access_denied(fn()=>st_event_audit($coordinator,202,'event.save','Out of scope'), 'Out-of-scope activity writes are rejected.');
    access_denied(fn()=>st_refresh_user(array_replace($coordinator,['session_version'=>0])), 'Refreshing mutation grants rejects a revoked session version.');
    access_denied(fn()=>st_scope_sql($coordinator,'o.event_id OR 1=1'), 'SQL column injection is rejected.');
    access_check(st_legacy_cms_id(9001) === 101 && st_can_legacy_event($coordinator,9001) && !st_can_legacy_event($coordinator,101), 'Legacy events map by slug even when numeric IDs collide.');
    $scope = st_legacy_scope_sql($coordinator,'e.id');
    $query = $db->prepare('SELECT e.id FROM events e WHERE '.$scope['sql']);
    $query->execute($scope['params']);
    access_check($query->fetchAll(PDO::FETCH_COLUMN) === [9001], 'Legacy exports use canonical event mapping.');
    $db->prepare('INSERT INTO az_participants(id,email,name,created_at) VALUES(?,?,?,?)')->execute([101,'one@example.com','One',gmdate('c')]);
    $db->prepare('INSERT INTO az_participants(id,email,name,created_at) VALUES(?,?,?,?)')->execute([202,'two@example.com','Two',gmdate('c')]);
    $db->prepare('INSERT INTO az_participants(id,email,name,created_at) VALUES(?,?,?,?)')->execute([303,'never@example.com','No orders',gmdate('c')]);
    $orderInsert = $db->prepare("INSERT INTO az_orders(id,public_id,participant_id,event_id,event_slug,ticket_type,snapshot,answers,quantity,unit_price,amount,state,environment,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,'general','{}','{}',1,100,100,'PAID','test',0,?,?)");
    foreach ([[11,'ORDER-ONE',101,101,'access-one'],[22,'ORDER-TWO',202,202,'access-two']] as $order) $orderInsert->execute([...$order,gmdate('c'),gmdate('c')]);
    $db->prepare('INSERT INTO az_tickets(id,ticket_id,order_id,participant_id,event_id,token,created_at) VALUES(?,?,?,?,?,?,?)')->execute([33,'TICKET-TWO',22,202,101,'not-a-real-token',gmdate('c')]);
    access_check((int)st_require_order($coordinator,11)['event_id'] === 101, 'Assigned order is accessible.');
    access_denied(fn()=>st_require_order($coordinator,22), 'Payment action cannot target another event.');
    access_denied(fn()=>st_require_ticket($coordinator,33), 'Forged redundant ticket event ID cannot bypass its parent order scope.');
    $scope = st_participant_scope_sql($coordinator,'p.id');
    $query = $db->prepare('SELECT p.id FROM az_participants p WHERE '.$scope['sql']);
    $query->execute($scope['params']);
    access_check($query->fetchAll(PDO::FETCH_COLUMN) === [101], 'Participant list excludes other events and people without assigned orders.');
    access_denied(fn()=>st_require_participant($coordinator,101,true), 'Scoped coordinator cannot disable a shared participant account.');
    access_denied(fn()=>st_set_assignments($master,$coordinatorId,[202,999999],false), 'Unavailable assignment is rejected atomically.');
    access_check(st_event_ids($coordinator) === [101], 'Invalid scope update retains previous valid assignments and session version.');
    $db->beginTransaction();
    st_set_assignments($master,$coordinatorId,[202],false);
    $db->rollBack();
    access_check(st_event_ids($coordinator) === [101], 'Outer staff-account transaction rollback includes assignments and session revocation.');
    st_set_assignments($master,$coordinatorId,[],true);
    $coordinator = access_user($coordinatorId);
    access_check(st_event_ids($coordinator) === null, 'Master can explicitly grant festival-wide event scope.');
    $db->prepare('UPDATE users SET active=0 WHERE id=?')->execute([$coordinatorId]);
    access_check(st_event_ids($coordinator) === [], 'Disabled global staff have no effective access.');
    access_check(st_staff_assignment_state($master,$coordinatorId)['event_scope'] === 'all', 'Master can inspect disabled staff assignments for management.');
    $db->prepare('UPDATE users SET active=1 WHERE id=?')->execute([$coordinatorId]);
    $coordinator = access_user($coordinatorId);
    st_set_assignments($master,$coordinatorId,[202],false);
    $coordinator = access_user($coordinatorId);
    $db->exec('DELETE FROM cms_content WHERE id=202');
    access_check(st_event_ids($coordinator) === [] && !st_can_event($coordinator,202), 'Orphaned assignments do not grant access to deleted events.');
    $audit = $db->query("SELECT COUNT(*) FROM cms_audit WHERE action='staff.events'")->fetchColumn();
    access_check((int)$audit === 3, 'Only committed assignment updates produce audit records.');
    st_install_access($db);
    access_check(true, 'Additive schema installation is idempotent.');
    echo $passed.' access checks passed.'.PHP_EOL;
} finally {
    $db = null;
}
