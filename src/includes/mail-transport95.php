<?php
declare(strict_types=1);

/** PHP mail() uses the host MTA. From addresses never multiply its shared quota. */
function az_mail_senders95(string $channel): array {
    $prefix=$channel==='otp'?'OTP':'NOTICE';$start=$channel==='otp'?1:3;$out=[];
    for($i=1;$i<=2;$i++){
        $address=getenv('ANAZORI_PHP_MAIL_'.$prefix.'_'.$i)?:'noreply'.($start+$i-1).'@ccsdu.in';
        if(!filter_var($address,FILTER_VALIDATE_EMAIL)||preg_match('/[\r\n]/',$address))throw new RuntimeException('Invalid PHP mail sender configuration.');
        $out[]=$address;
    }
    return $out;
}
function az_mail_limits95(): array {
    $read=fn($key,$default)=>max(1,min(100000,(int)(getenv('ANAZORI_PHP_MAIL_'.$key)?:$default)));
    return ['day'=>$read('DAILY_LIMIT',90),'minute'=>$read('PER_MINUTE',8),'sender_day'=>$read('SENDER_DAILY_LIMIT',45),'sender_minute'=>$read('SENDER_PER_MINUTE',4)];
}
function az_install_mail95(PDO $db): void {
    if($db->query("SELECT value FROM cms_settings WHERE setting_key='mail_schema95'")->fetchColumn())return;
    $sqlite=$db->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite';$id=$sqlite?'INTEGER PRIMARY KEY AUTOINCREMENT':'INT AUTO_INCREMENT PRIMARY KEY';$text=$sqlite?'TEXT':'MEDIUMTEXT';
    $columns=array_column($db->query($sqlite?'PRAGMA table_info(az_mail_deliveries89)':'SHOW COLUMNS FROM az_mail_deliveries89')->fetchAll(),$sqlite?'name':'Field');
    foreach(['sender'=>"VARCHAR(254) NOT NULL DEFAULT ''",'channel'=>"VARCHAR(10) NOT NULL DEFAULT ''"] as $name=>$type)if(!in_array($name,$columns,true))$db->exec("ALTER TABLE az_mail_deliveries89 ADD COLUMN $name $type");
    $db->exec("CREATE TABLE IF NOT EXISTS az_mail_sender95 (sender VARCHAR(254) PRIMARY KEY, cooldown_until BIGINT NOT NULL DEFAULT 0)");
    $db->exec("CREATE TABLE IF NOT EXISTS az_mail_alerts95 (id $id, dedupe_key VARCHAR(64) NOT NULL UNIQUE, message $text NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'pending', available_at BIGINT NOT NULL, lease_until BIGINT NOT NULL DEFAULT 0, claim_token VARCHAR(64), attempts INT NOT NULL DEFAULT 0, created_at BIGINT NOT NULL)");
    try{$db->exec('CREATE INDEX '.($sqlite?'IF NOT EXISTS ':'').'az_mail_sender_budget95 ON az_mail_deliveries89(sender,started_at)');}catch(PDOException $e){if((int)($e->errorInfo[1]??0)!==1061)throw $e;}
    az_schema_marker($db,'mail_schema95');
}
function az_mail_alert95(PDO $db,string $reason,string $detail): void {
    $insert=$db->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite'?'INSERT OR IGNORE':'INSERT IGNORE';
    $message="ANAZORI PHP-mail notice\n\n".$detail."\n\nTime: ".gmdate('c')."\nSender addresses share the hosting account's PHP-mail quota. Check the host's mail logs for delivery or provider quota details.\n";
    $db->prepare($insert.' INTO az_mail_alerts95(dedupe_key,message,available_at,created_at) VALUES(?,?,?,?)')->execute([hash('sha256',$reason.'|'.(int)floor(time()/3600)),$message,time(),time()]);
}
/** Atomic reservations include failures because the provider may already have accepted them. */
function az_mail_reserve95(string $channel): array {
    if(!in_array($channel,['otp','notice','alert'],true))throw new InvalidArgumentException('Invalid mail channel.');
    $db=cms_db();if($db->inTransaction())throw new LogicException('Mail must run outside application transactions.');
    $all=array_merge(az_mail_senders95('otp'),az_mail_senders95('notice'));if(count(array_unique($all))!==4)throw new RuntimeException('Configure four distinct PHP mail senders.');
    $pair=az_mail_senders95($channel==='otp'?'otp':'notice');$limits=az_mail_limits95();$now=time();$throttle=0;$reservation=[];
    $db->beginTransaction();
    try{
        az_lock($db);$q=$db->prepare('SELECT COUNT(*) FROM az_mail_deliveries89 WHERE started_at>?');
        $q->execute([$now-86400]);$daily=(int)$q->fetchColumn();$q->execute([$now-60]);$minute=(int)$q->fetchColumn();
        $alertReserve=min(2,(int)floor($limits['day']/10));$otpReserve=min(20,(int)floor($limits['day']/5));
        $ceiling=$limits['day']-($channel==='notice'?$otpReserve+$alertReserve:($channel==='otp'?$alertReserve:0));
        $minuteCeiling=$limits['minute']-($channel==='notice'?min(3,(int)floor($limits['minute']/3)):($channel==='otp'?min(1,(int)floor($limits['minute']/4)):0));
        if($daily>=$ceiling||$minute>=$minuteCeiling){
            $throttle=$daily>=$ceiling?900:65;
            if($channel!=='alert')az_mail_alert95($db,'shared-budget','Configured shared PHP-mail '.($daily>=$ceiling?'daily':'minute').' budget reached. Delivery is deferred; switching addresses cannot bypass this shared limit.');
        }else{
            $key='mail_active95_'.($channel==='otp'?'otp':'notice');$q=$db->prepare('SELECT value FROM cms_settings WHERE setting_key=?');$q->execute([$key]);$active=$q->fetchColumn();$active=in_array($active,$pair,true)?$active:$pair[0];
            $candidates=[$active,$pair[0]===$active?$pair[1]:$pair[0]];$sender=null;$reason='configured sender budget reached';
            foreach($candidates as $candidate){
                $q=$db->prepare('SELECT cooldown_until FROM az_mail_sender95 WHERE sender=?');$q->execute([$candidate]);if((int)$q->fetchColumn()>$now){$reason='sender transport failure cooldown';continue;}
                $q=$db->prepare('SELECT COUNT(*) FROM az_mail_deliveries89 WHERE sender=? AND started_at>?');$q->execute([$candidate,$now-86400]);$day=(int)$q->fetchColumn();$q->execute([$candidate,$now-60]);$min=(int)$q->fetchColumn();
                // Reserve alert headroom within notification senders as well.
                $senderCeiling=$limits['sender_day']-($channel==='notice'?min(1,(int)floor($limits['sender_day']/10)):0);
                if($day>=$senderCeiling||$min>=$limits['sender_minute'])continue;$sender=$candidate;break;
            }
            if($sender===null){$throttle=65;if($channel!=='alert')az_mail_alert95($db,'pair-budget-'.$channel,'Both '.$channel.' senders are unavailable under configured limits or cooldowns. Messages are deferred.');}
            else{
                cms_put_setting($key,$sender);
                if($sender!==$active)az_mail_alert95($db,'switch-'.$active.'-'.$sender.'-'.$reason,'Sender changed for '.($channel==='otp'?'otp':'notifications / alerts').': '.$active.' → '.$sender.'. Reason: '.$reason.'. This is an application allocation or transport failure, not proof of a provider quota.');
                $db->prepare('INSERT INTO az_mail_deliveries89(started_at,sender,channel) VALUES(?,?,?)')->execute([$now,$sender,$channel]);$reservation=['id'=>(int)$db->lastInsertId(),'sender'=>$sender];
            }
        }
        $db->commit();
    }catch(Throwable $e){if($db->inTransaction())$db->rollBack();throw $e;}
    if($throttle)throw new AzMailThrottle89($throttle);return $reservation;
}
function az_mail_native95(string $sender,string $email,string $subject,string $body,string $html): void {
    if(getenv('ANAZORI_TEST_MODE')==='1'){
        // Test mode must never fall through to a real mail transport.
        $dir=realpath(getenv('ANAZORI_TEST_OUTBOX')?:'');$root=strtolower(str_replace('\\','/',realpath(__DIR__.'/..')).'/');
        if(!$dir||str_starts_with(strtolower(str_replace('\\','/',$dir)).'/',$root))throw new RuntimeException('Test mail storage must be outside the website.');
        if(in_array($sender,explode(',',getenv('ANAZORI_TEST_MAIL_FAIL_SENDERS')?:''),true))throw new RuntimeException('Simulated transport failure.');
        if(file_put_contents($dir.'/'.bin2hex(random_bytes(12)).'.json',json_encode(['from'=>$sender,'to'=>$email,'subject'=>$subject,'body'=>$body,'html'=>$html],JSON_THROW_ON_ERROR),LOCK_EX)===false)throw new RuntimeException('Test outbox unavailable.');return;
    }
    $mail=new PHPMailer\PHPMailer\PHPMailer(true);$mail->isMail();$mail->CharSet='UTF-8';$mail->Encoding='base64';$mail->setFrom($sender,'ANAZORI · CCSA');$mail->Sender=$sender;$mail->addAddress($email);$mail->Subject=$subject;$mail->isHTML($html!=='');$mail->Body=$html!==''?$html:$body;$mail->AltBody=$body;$mail->send();
}
function az_mail_deliver95(string $channel,string $email,string $subject,string $body,string $html=''): void {
    if(!filter_var($email,FILTER_VALIDATE_EMAIL)||preg_match('/[\r\n]/',$email.$subject))throw new InvalidArgumentException('Invalid email message.');
    for($attempt=0;$attempt<2;$attempt++){
        $delivery=az_mail_reserve95($channel);
        try{az_mail_native95($delivery['sender'],$email,$subject,$body,$html);cms_db()->prepare("UPDATE az_mail_deliveries89 SET status='sent' WHERE id=?")->execute([$delivery['id']]);return;}
        catch(Throwable $e){
            $db=cms_db();$db->beginTransaction();try{az_lock($db);$db->prepare("UPDATE az_mail_deliveries89 SET status='failed' WHERE id=?")->execute([$delivery['id']]);
                $db->prepare('DELETE FROM az_mail_sender95 WHERE sender=?')->execute([$delivery['sender']]);$db->prepare('INSERT INTO az_mail_sender95(sender,cooldown_until) VALUES(?,?)')->execute([$delivery['sender'],time()+900]);
                if($channel!=='alert')az_mail_alert95($db,'failure-'.$delivery['sender'],'PHP mail transport rejected a message from '.$delivery['sender'].'. The sender is on a 15-minute cooldown and its paired sender will be tried. The host did not provide a reliable quota reason.');$db->commit();
            }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
            error_log('ANAZORI PHP mail transport failed for '.$delivery['sender']);
        }
    }
    throw new RuntimeException('We could not deliver the email. Please try again or contact the organisers.');
}
/** Alerts use only notification senders; leases avoid duplicate cron/request sends. */
function az_mail_flush_alerts95(int $limit=2): int {
    static $running=false;if($running||!az_mail_delivery_available())return 0;$running=true;$sent=0;$db=cms_db();
    try{for($i=0;$i<$limit;$i++){
        $db->beginTransaction();try{az_lock($db);$q=$db->prepare("SELECT * FROM az_mail_alerts95 WHERE (status='pending' OR (status='sending' AND lease_until<?)) AND available_at<=? ORDER BY id LIMIT 1");$q->execute([time(),time()]);$job=$q->fetch();if(!$job){$db->commit();break;}$claim=bin2hex(random_bytes(24));$db->prepare("UPDATE az_mail_alerts95 SET status='sending',claim_token=?,lease_until=?,attempts=attempts+1 WHERE id=?")->execute([$claim,time()+300,$job['id']]);$db->commit();}catch(Throwable $e){if($db->inTransaction())$db->rollBack();throw $e;}
        $status='sent';$retry=time();try{az_mail_deliver95('alert',ANAZORI_SUPER_EMAIL,'ANAZORI mail quota / sender notice',$job['message']);$sent++;}
        catch(Throwable $e){$status='pending';$retry+= $e instanceof AzMailThrottle89?$e->retryAfter:min(21600,300*(2**min(6,(int)$job['attempts'])));}
        $db->prepare('UPDATE az_mail_alerts95 SET status=?,available_at=?,lease_until=0,claim_token=NULL WHERE id=? AND claim_token=?')->execute([$status,$retry,$job['id'],$claim]);if($status==='pending')break;
    }}finally{$running=false;}return $sent;
}
