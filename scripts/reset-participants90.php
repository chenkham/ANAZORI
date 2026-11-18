<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'){http_response_code(404);exit;}
require_once __DIR__.'/../src/includes/commerce.php';
require_once __DIR__.'/database-export90.php';
$db=cms_db();
// This maintenance command is deliberately restricted to the local preparation database.
if(APP_ENV!=='development'||DB_DRIVER!=='mysql'||!in_array(DB_HOST,['localhost','127.0.0.1','::1'],true))throw new RuntimeException('Participant reset is restricted to the local development MySQL database.');
$clear=['az_checkins','az_ticket_blocks','az_tickets','az_refunds','az_payment_reviews','az_manual_payments','az_payment_proofs','az_form_reviews','az_form_payment_refs','az_form_responses','az_draft_files','az_checkout_drafts','az_registration_files','az_mail_jobs89','az_webhooks','st_settlement_orders','st_settlements','st_reconciliations','st_closeouts','az_event_reconciliations','az_orders','submissions','az_participants'];
$plan=[];foreach($clear as $table)$plan[$table]=(int)$db->query('SELECT COUNT(*) FROM `'.$table.'`')->fetchColumn();
if(!in_array('--execute',$_SERVER['argv'],true)){echo json_encode(['dry_run'=>true,'participant_records'=>$plan,'staff_preserved'=>(int)$db->query('SELECT COUNT(*) FROM users')->fetchColumn()],JSON_PRETTY_PRINT)."\n";exit;}
$backup=dirname(__DIR__).'/.local/participant-reset90/'.gmdate('Ymd-His').'-'.bin2hex(random_bytes(3));
if(!mkdir($backup,0700,true))throw new RuntimeException('Cannot create the recovery folder.');
$protected=['users','st_event_assignments','cms_content','cms_media','events','st_budgets','st_expenses','st_finance_evidence','st_finance_ledger'];
$hashes=[];
foreach($protected as $table)$hashes[$table]=hash('sha256',json_encode($db->query('SELECT * FROM `'.$table.'`')->fetchAll(),JSON_THROW_ON_ERROR));
$files=[];
$root=dirname(__DIR__);
$sources=[
 'registration-files'=>['dir'=>getenv('ANAZORI_REGISTRATION_FILE_DIR')?:$root.'/anazori-private/registration-files','names'=>$db->query('SELECT filename FROM az_registration_files')->fetchAll(PDO::FETCH_COLUMN)],
 'payment-proofs'=>['dir'=>getenv('ANAZORI_PAYMENT_PROOF_DIR')?:$root.'/anazori-private/payment-proofs','names'=>$db->query('SELECT filename FROM az_payment_proofs')->fetchAll(PDO::FETCH_COLUMN)],
 'legacy-proofs'=>['dir'=>$root.'/src/uploads/proofs','names'=>$db->query("SELECT payment_proof FROM submissions WHERE payment_proof IS NOT NULL AND payment_proof<>''")->fetchAll(PDO::FETCH_COLUMN)],
];
$db->beginTransaction();
try{
    az_lock($db);
    $allCounts=az_mysql_export90($db,$backup.'/full-database.sql');
    $keyPath=az_application_key_path90();if(is_file($keyPath)&&!copy($keyPath,$backup.'/application-key'))throw new RuntimeException('Application-key backup failed.');
    foreach($sources as $label=>$source){
        foreach(array_unique($source['names']) as $name){
            $name=basename(str_replace('\\','/',(string)$name));if($name===''||$name==='.'||$name==='..')throw new RuntimeException('Invalid private filename.');
            $path=$source['dir'].DIRECTORY_SEPARATOR.$name;if(!is_file($path))continue;
            if(is_link($path))throw new RuntimeException('Refusing a linked upload during reset.');
            $directory=$backup.'/'.$label;if(!is_dir($directory))mkdir($directory,0700);
            if(!copy($path,$directory.'/'.$name)||!hash_equals(hash_file('sha256',$path),hash_file('sha256',$directory.'/'.$name)))throw new RuntimeException('Private-upload backup failed.');
            $files[]=['path'=>$path,'backup'=>$directory.'/'.$name];
        }
    }
    foreach($clear as $table)$db->exec('DELETE FROM `'.$table.'`');
    $db->exec("DELETE FROM az_auth_events WHERE user_kind='participant'");
    $db->exec("DELETE FROM az_challenges WHERE user_kind='participant'");
    // Review/export logs can contain deleted participant details; staff/content activity remains.
    $db->exec("DELETE FROM st_event_activity WHERE action LIKE 'form.%' AND action<>'form.publish' OR action LIKE 'payment.%' OR action LIKE 'ticket.%' OR action LIKE 'participant.%' OR action LIKE 'submission.%'");
    $db->exec("DELETE FROM cms_audit WHERE action LIKE 'submission.%' OR action LIKE 'participant.%' OR action LIKE 'payment.%' OR action LIKE 'ticket.%' OR action LIKE 'form.%' AND action<>'form.publish' OR action='finance.export'");
    $db->exec("DELETE FROM st_finance_audit WHERE action IN ('export','settlement_record','reconcile','close','reopen')");
    $db->exec("DELETE FROM st_finance_commands WHERE action IN ('settlement_record','reconcile','close','reopen')");
    // HMAC rate-limit keys cannot be attributed back to an account; only expired buckets are pruned.
    $db->prepare('DELETE FROM az_rate_limits WHERE expires_at<?')->execute([time()]);
    foreach($protected as $table)if(!hash_equals($hashes[$table],hash('sha256',json_encode($db->query('SELECT * FROM `'.$table.'`')->fetchAll(),JSON_THROW_ON_ERROR))))throw new RuntimeException('A preserved table changed; reset rolled back.');
    $db->commit();
}catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
$removed=0;$retained=[];
// Only exact files copied and verified above are removed; no recursive/private-directory delete.
foreach($files as $file){if(unlink($file['path']))$removed++;else $retained[]=$file['path'];}
$manifest=['created_at'=>gmdate('c'),'before'=>$allCounts,'deleted'=>$plan,'preserved_hashes'=>$hashes,'private_files_removed'=>$removed,'private_files_needing_cleanup'=>$retained];
file_put_contents($backup.'/manifest.json',json_encode($manifest,JSON_PRETTY_PRINT|JSON_THROW_ON_ERROR));
echo 'Participant reset complete. Staff, events, forms, media and organiser accounting preserved. Recovery folder: '.str_replace('\\','/',$backup)."\n";
echo 'Private uploaded files removed: '.$removed.'. Files needing cleanup: '.count($retained)."\n";
if($retained)exit(1);
