<?php
declare(strict_types=1);
putenv('ANAZORI_DB_PATH=:memory:');putenv('ANAZORI_TEST_MODE=1');
require __DIR__.'/../src/includes/commerce.php';
$db=cms_db();$checks=0;
function workflow_check(bool $valid,string $description): void {global $checks;if(!$valid)throw new RuntimeException($description);$checks++;}
$db->prepare("INSERT INTO users(username,email,password_hash,role,permissions,event_scope,must_change_password) VALUES('migration-coordinator','migration@example.invalid',?,'COORDINATOR','[\"gallery.view\"]','assigned',0)")->execute([password_hash('Migration-Check-2026!',PASSWORD_DEFAULT)]);
$id=(int)$db->lastInsertId();$event=(int)$db->query("SELECT id FROM cms_content WHERE type='event' ORDER BY id LIMIT 1")->fetchColumn();
$db->prepare('INSERT INTO st_event_assignments(user_id,event_id,assigned_by,assigned_at) VALUES(?,?,1,?)')->execute([$id,$event,gmdate('c')]);
$old=st_finance_query($db,'SELECT * FROM users WHERE id=?',[$id])[0];
$db->exec("DELETE FROM cms_settings WHERE setting_key='coordinator_workflow_schema'");
st_install_coordinator_workflow($db);
$staff=st_finance_query($db,'SELECT * FROM users WHERE id=?',[$id])[0];$permissions=json_decode($staff['permissions'],true);
foreach(st_coordinator_permissions() as $key)workflow_check(in_array($key,$permissions,true),'Migration grants '.$key);
workflow_check(in_array('gallery.view',$permissions,true),'Unrelated saved permissions survive');
workflow_check(st_event_ids($staff)===[$event],'Event scope stays assigned to the same event');
workflow_check((int)$staff['session_version']===(int)$old['session_version']+1,'Changed grants revoke older sessions');
workflow_check(st_event_ids($old)===[],'The old session cannot retain event access');
st_install_coordinator_workflow($db);$again=st_finance_query($db,'SELECT * FROM users WHERE id=?',[$id])[0];
workflow_check($again['session_version']===$staff['session_version'],'Migration reruns do not revoke another session');
workflow_check($again['password_hash']===$old['password_hash'],'Coordinator passwords are retained');
echo "PASS $checks coordinator migration and event-scope checks.\n";
