<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require_once __DIR__.'/commerce.php';
try {
    $db=cms_db();
    if(in_array('--status',$_SERVER['argv']??[],true)){
        $heartbeat=(int)$db->query("SELECT value FROM cms_settings WHERE setting_key='mail_worker_heartbeat89'")->fetchColumn();
        echo json_encode(['environment'=>APP_ENV,'transport'=>'php_mail','transport_available'=>az_mail_delivery_available(),'notifications_enabled'=>az_mail_notifications_enabled89(),'cron_last_run'=>$heartbeat?gmdate('c',$heartbeat):null,'cron_recent'=>$heartbeat>time()-600,'limits'=>az_mail_limits95(),'queue'=>$db->query('SELECT kind,status,COUNT(*) AS jobs FROM az_mail_jobs89 GROUP BY kind,status')->fetchAll(PDO::FETCH_ASSOC)],JSON_THROW_ON_ERROR).PHP_EOL;
        exit;
    }
    $test = getenv('ANAZORI_TEST_MODE') === '1' && getenv('ANAZORI_TEST_OUTBOX');
    if (APP_ENV !== 'production' && !$test) throw new RuntimeException('The email worker runs on production, or with an isolated test outbox.');
    if (!az_mail_delivery_available()) throw new RuntimeException('Enable the host PHP mail service before running the email cron job.');
    // Run manually after fixing a delivery problem, never in the recurring cron command.
    if (in_array('--retry-failed',$_SERVER['argv'] ?? [],true)) cms_db()->exec("UPDATE az_mail_jobs89 SET status='pending',attempts=0,available_at=0,last_error=NULL WHERE status='failed'");
    $result=az_run_mail_worker89(5);
    $result['notifications_enabled']=az_mail_notifications_enabled89();
    $result['pending_total']=(int)$db->query("SELECT COUNT(*) FROM az_mail_jobs89 WHERE status IN ('pending','sending')")->fetchColumn();
    $result['failed_total']=(int)$db->query("SELECT COUNT(*) FROM az_mail_jobs89 WHERE status='failed'")->fetchColumn();
    $result['transport']='php_mail';
    echo json_encode($result,JSON_THROW_ON_ERROR).PHP_EOL;
} catch (Throwable $error) {
    fwrite(STDERR,'ANAZORI email worker could not finish. Check private configuration and the server error log.'.PHP_EOL);
    error_log('ANAZORI email worker: '.$error->getMessage()); exit(1);
}
