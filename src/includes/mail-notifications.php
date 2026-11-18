<?php
declare(strict_types=1);
require_once __DIR__.'/mail-templates.php';
require_once __DIR__.'/mail-policy101.php';

// Submission receipts, approved tickets and reminders use the notification sender pair.
function az_mail_notifications_enabled89(): bool { return getenv('ANAZORI_MAIL_NOTIFICATIONS') !== '0'; }

function az_install_mail89(PDO $db): void {
    if ($db->query("SELECT value FROM cms_settings WHERE setting_key='mail_schema89'")->fetchColumn()) return;
    $sqlite = $db->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite';
    $id = $sqlite ? 'INTEGER PRIMARY KEY AUTOINCREMENT' : 'INT AUTO_INCREMENT PRIMARY KEY';
    $text = $sqlite ? 'TEXT' : 'MEDIUMTEXT';
    $db->exec("CREATE TABLE IF NOT EXISTS az_mail_jobs89 (id $id, dedupe_key VARCHAR(64) NOT NULL UNIQUE, kind VARCHAR(40) NOT NULL, payload $text NOT NULL, order_id INT, participant_id INT, event_time BIGINT NOT NULL DEFAULT 0, status VARCHAR(20) NOT NULL DEFAULT 'pending', attempts INT NOT NULL DEFAULT 0, available_at BIGINT NOT NULL, lease_until BIGINT NOT NULL DEFAULT 0, claim_token VARCHAR(64), created_at BIGINT NOT NULL, sent_at BIGINT, last_error VARCHAR(40))");
    $db->exec("CREATE TABLE IF NOT EXISTS az_mail_deliveries89 (id $id, started_at BIGINT NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'reserved')");
    foreach (['az_mail_ready89'=>'az_mail_jobs89(status,available_at,id)', 'az_mail_reminder89'=>'az_mail_jobs89(order_id,kind,event_time)', 'az_mail_budget89'=>'az_mail_deliveries89(started_at)'] as $name=>$definition) {
        try { $db->exec('CREATE INDEX '.($sqlite ? 'IF NOT EXISTS ' : '').$name.' ON '.$definition); }
        catch (PDOException $error) { if ((int)($error->errorInfo[1] ?? 0) !== 1061) throw $error; }
    }
    az_schema_marker($db, 'mail_schema89');
}

final class AzMailThrottle89 extends RuntimeException {
    public function __construct(public readonly int $retryAfter) { parent::__construct('Email delivery is busy. Please wait before requesting another code.'); }
}

/** Call inside the business transaction so an acknowledgement cannot outlive a rollback. */
function az_queue_mail89(string $key, string $kind, array $data, ?int $orderId = null, ?int $participantId = null, int $eventTime = 0): void {
    if (!az_mail_notifications_enabled89() || !in_array($kind,ANAZORI_NOTICE_KINDS101,true)) return;
    if($orderId===null||$participantId===null)throw new LogicException('Ticket notifications require a registration.');
    if (!filter_var($data['email'] ?? '', FILTER_VALIDATE_EMAIL)) throw new InvalidArgumentException('Invalid notification recipient.');
    $db = cms_db();
    $payload = az_encrypt(json_encode($data, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
    $insert = $db->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite' ? 'INSERT OR IGNORE' : 'INSERT IGNORE';
    $query=$db->prepare($insert.' INTO az_mail_jobs89(dedupe_key,kind,payload,order_id,participant_id,event_time,available_at,created_at) VALUES(?,?,?,?,?,?,?,?)');
    $query->execute([hash('sha256',$key),$kind,$payload,$orderId,$participantId,$eventTime,time(),time()]);
    if($query->rowCount()>0)az_mail_after_request107();
}

/** Try committed notices after the response; cron remains responsible for retries and reminders. */
function az_mail_after_request107(): void {
    static $registered=false;
    if($registered||PHP_SAPI==='cli')return;
    $registered=true;
    register_shutdown_function(static function(): void {
        try{
            if(cms_db()->inTransaction()||!az_mail_notifications_enabled89()||!az_mail_delivery_available())return;
            if(session_status()===PHP_SESSION_ACTIVE)session_write_close();
            if(function_exists('fastcgi_finish_request'))fastcgi_finish_request();
            az_run_mail_worker89(2);
        }catch(Throwable){error_log('ANAZORI notification remains queued; run the email cron and check its output.');}
    });
}

function az_notify_order89(array $order, string $kind, string $version = '', array $extra = []): void {
    if (!az_mail_notifications_enabled89() || !in_array($kind,ANAZORI_NOTICE_KINDS101,true)) return;
    if (($order['environment'] ?? '') !== 'live') return;
    $q = cms_db()->prepare('SELECT id,name,email,active FROM az_participants WHERE id=?');
    $q->execute([$order['participant_id']]); $person = $q->fetch();
    if (!$person || !$person['active']) return;
    $snapshot = json_decode($order['snapshot'],true,512,JSON_THROW_ON_ERROR);
    $data = ['email'=>$person['email'], 'name'=>$person['name'], 'event'=>$snapshot['title'] ?? $order['event_slug'], 'game'=>$snapshot['game'] ?? '', 'category'=>$snapshot['type'] ?? '', 'people'=>(string)($snapshot['people'] ?? 1), 'venue'=>$snapshot['venue'] ?? '', 'when'=>az_mail_event_time($snapshot['starts_at'] ?? ''), 'reference'=>$order['public_id'], 'amount'=>az_money((int)$order['amount']), 'path'=>'/dashboard.php','event_path'=>'/event.php?name='.$order['event_slug']];
    az_queue_mail89($kind.':'.$order['id'].':'.$version, $kind, array_replace($data,$extra), (int)$order['id'], (int)$person['id']);
}

function az_notify_welcome89(array $person): void { /* No account welcome mail: OTP and the three requested notifications only. */ }

/** Leases keep mail outside transactions and prevent simultaneous request/cron delivery. */
function az_run_mail_worker89(int $limit = 5): array {
    $result = ['scheduled'=>0,'sent'=>0,'skipped'=>0,'retried'=>0,'failed'=>0];
    az_mail_flush_alerts95();
    if (!az_mail_notifications_enabled89() || !az_mail_delivery_available()) return $result;
    $db = cms_db(); $now = time();
    if(PHP_SAPI==='cli')cms_put_setting('mail_worker_heartbeat89',(string)$now);
    $allowedKinds=implode(',',array_map([$db,'quote'],ANAZORI_NOTICE_KINDS101));
    $purge=$db->prepare("UPDATE az_mail_jobs89 SET status='skipped',lease_until=0,claim_token=NULL,last_error='notification_disabled' WHERE kind NOT IN (".$allowedKinds.") AND (status IN ('pending','failed') OR (status='sending' AND lease_until<?))");$purge->execute([$now]);$result['skipped']+=(int)$purge->rowCount();
    $db->prepare('DELETE FROM az_mail_deliveries89 WHERE started_at<?')->execute([$now - 30*86400]);
    $db->prepare("UPDATE az_mail_jobs89 SET status='pending',claim_token=NULL WHERE status='sending' AND lease_until<?")->execute([$now]);
    $db->exec("UPDATE az_mail_jobs89 SET status='failed',last_error='retry_limit' WHERE status='pending' AND attempts>=8");
    $result['scheduled'] = az_schedule_reminders89($now);
    for ($i=0; $i<max(1,min(50,$limit)); $i++) {
        $db->beginTransaction();
        try {
            az_lock($db);
            $q = $db->prepare("SELECT * FROM az_mail_jobs89 WHERE status='pending' AND available_at<=? AND attempts<8 ORDER BY id LIMIT 1"); $q->execute([time()]); $job = $q->fetch();
            if (!$job) { $db->commit(); break; }
            $claim = bin2hex(random_bytes(24));
            $db->prepare("UPDATE az_mail_jobs89 SET status='sending',lease_until=?,claim_token=?,attempts=attempts+1 WHERE id=?")->execute([time()+300,$claim,$job['id']]);
            $db->commit();
        } catch (Throwable $error) { if ($db->inTransaction()) $db->rollBack(); throw $error; }
        $status = 'sent'; $errorCode = null; $next = time(); $refundAttempt = 0;
        try {
            $data = json_decode(az_decrypt($job['payload']),true,512,JSON_THROW_ON_ERROR);
            if (!az_mail_job_current89($job,$data)) { $status = 'skipped'; }
            else {
                $data=az_mail_data_current101($job,$data);
                $message = az_mail_template($job['kind'],$data);
                az_send_mail($data['email'],$message['subject'],$message['body'],$message['html'],false);
            }
            $result[$status]++;
        } catch (AzMailNotDue101 $error) {
            $status='pending';$next=$error->sendAt;$errorCode='reminder_not_due';$refundAttempt=1;$result['retried']++;
        } catch (AzMailThrottle89 $error) {
            $status = 'pending'; $next += $error->retryAfter; $errorCode = 'sending_limit'; $refundAttempt = 1; $result['retried']++;
        } catch (Throwable $error) {
            $status = (int)$job['attempts'] + 1 >= 8 ? 'failed' : 'pending';
            $next += min(21600,60 * (2 ** min(8,(int)$job['attempts'])));
            $errorCode = 'delivery_failed'; $result[$status === 'failed' ? 'failed' : 'retried']++;
            error_log('ANAZORI email job '.$job['id'].' will '.($status === 'failed' ? 'need attention.' : 'retry.'));
        }
        $db->prepare('UPDATE az_mail_jobs89 SET status=?,sent_at=?,available_at=?,lease_until=0,claim_token=NULL,last_error=?,attempts=attempts-? WHERE id=? AND claim_token=?')->execute([$status,$status==='sent'?time():null,$next,$errorCode,$refundAttempt,$job['id'],$claim]);
        if ($errorCode === 'sending_limit') break;
    }
    return $result;
}
