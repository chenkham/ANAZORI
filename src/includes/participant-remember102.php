<?php
declare(strict_types=1);

const ANAZORI_REMEMBER_TTL102=30*86400;

/** Separate from PHP's short session cookie; never used for staff authentication. */
function az_install_remember102(PDO $db): void {
    if($db->query("SELECT value FROM cms_settings WHERE setting_key='remember_schema102'")->fetchColumn())return;
    $db->exec("CREATE TABLE IF NOT EXISTS az_remember_tokens102 (selector VARCHAR(32) PRIMARY KEY,participant_id INT NOT NULL,validator_hash VARCHAR(64) NOT NULL,previous_hash VARCHAR(64),previous_until BIGINT NOT NULL DEFAULT 0,email_hash VARCHAR(64) NOT NULL,session_version INT NOT NULL,auth_method VARCHAR(30) NOT NULL,created_at BIGINT NOT NULL,last_used_at BIGINT NOT NULL,expires_at BIGINT NOT NULL)");
    $sqlite=$db->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite';
    foreach(['az_remember_expiry102'=>'az_remember_tokens102(expires_at)','az_remember_user102'=>'az_remember_tokens102(participant_id,last_used_at)'] as $name=>$definition){
        try{$db->exec('CREATE INDEX '.($sqlite?'IF NOT EXISTS ':'').$name.' ON '.$definition);}
        catch(PDOException $error){if((int)($error->errorInfo[1]??0)!==1061)throw $error;}
    }
    az_schema_marker($db,'remember_schema102');
}

function az_remember_secure102(): bool {return APP_ENV==='production'||(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off');}
function az_remember_name102(): string {return az_remember_secure102()?'__Host-anazori_remember102':'anazori_remember102';}
function az_remember_cookie102(string $value,int $expires): void {
    if(PHP_SAPI==='cli'||headers_sent())return;
    if(!setcookie(az_remember_name102(),$value,['expires'=>$expires,'path'=>'/','secure'=>az_remember_secure102(),'httponly'=>true,'samesite'=>'Lax']))throw new RuntimeException('Could not keep this browser signed in.');
    if($value==='')unset($_COOKIE[az_remember_name102()]);else $_COOKIE[az_remember_name102()]=$value;
}
function az_remember_parts102(): ?array {
    $value=$_COOKIE[az_remember_name102()]??'';
    return is_string($value)&&preg_match('/^([a-f0-9]{32})\.([a-f0-9]{64})$/D',$value,$match)?[$match[1],$match[2]]:null;
}
function az_participant_clear102(): void {
    if(isset($_SESSION['verify_challenge']))unset($_SESSION['az_challenges'][$_SESSION['verify_challenge']]);
    unset($_SESSION['participant_id'],$_SESSION['participant_version'],$_SESSION['participant_email'],$_SESSION['participant_method'],$_SESSION['participant_remember102'],$_SESSION['profile_next'],$_SESSION['participant_next'],$_SESSION['verify_challenge'],$_SESSION['verify_flash99']);
}

/** Revoke this browser only. A selector from a request cannot revoke another user. */
function az_remember_revoke102(?int $participantId=null): void {
    $participantId??=(int)($_SESSION['participant_id']??0);
    $selector=$_SESSION['participant_remember102']??(az_remember_parts102()[0]??'');
    if($participantId>0&&is_string($selector)&&preg_match('/^[a-f0-9]{32}$/D',$selector)){
        cms_db()->prepare('DELETE FROM az_remember_tokens102 WHERE selector=? AND participant_id=?')->execute([$selector,$participantId]);
    }
    az_remember_cookie102('',time()-3600);
    unset($_SESSION['participant_remember102']);
}

/** Issue only after the normal password/Google/session checks have authenticated this user. */
function az_remember_issue102(array $participant,string $method): void {
    if(PHP_SAPI==='cli'||headers_sent())return;
    $db=cms_db();if($db->inTransaction())return;
    $now=time();$expires=$now+ANAZORI_REMEMBER_TTL102;
    $selector=bin2hex(random_bytes(16));$validator=bin2hex(random_bytes(32));
    $method=$method==='google'?'google':'email_password';
    $db->beginTransaction();
    try{
        az_lock($db);
        $db->prepare('DELETE FROM az_remember_tokens102 WHERE expires_at<=?')->execute([$now]);
        $old=$_SESSION['participant_remember102']??(az_remember_parts102()[0]??'');
        if(is_string($old))$db->prepare('DELETE FROM az_remember_tokens102 WHERE selector=? AND participant_id=?')->execute([$old,$participant['id']]);
        $db->prepare('INSERT INTO az_remember_tokens102(selector,participant_id,validator_hash,email_hash,session_version,auth_method,created_at,last_used_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)')->execute([$selector,$participant['id'],hash('sha256',$validator),hash('sha256',strtolower($participant['email'])),(int)$participant['session_version'],$method,$now,$now,$expires]);
        // Keep at most ten remembered browsers per account.
        $query=$db->prepare('SELECT selector FROM az_remember_tokens102 WHERE participant_id=? AND selector<>? ORDER BY last_used_at DESC,created_at DESC,selector DESC');
        $query->execute([$participant['id'],$selector]);
        foreach(array_slice($query->fetchAll(PDO::FETCH_COLUMN),9) as $old)$db->prepare('DELETE FROM az_remember_tokens102 WHERE selector=?')->execute([$old]);
        $db->commit();
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
    $_SESSION['participant_remember102']=$selector;
    az_remember_cookie102($selector.'.'.$validator,$expires);
}

/** Token revocation also ends PHP sessions restored from that browser token. */
function az_remember_session_current102(array $participant): bool {
    $selector=$_SESSION['participant_remember102']??'';
    if($selector===''){az_remember_issue102($participant,$_SESSION['participant_method']??'email_password');return true;}
    $query=cms_db()->prepare('SELECT expires_at,session_version,email_hash FROM az_remember_tokens102 WHERE selector=? AND participant_id=?');
    $query->execute([$selector,$participant['id']]);$row=$query->fetch();
    if($row&&(int)$row['expires_at']>time()&&(int)$row['session_version']===(int)$participant['session_version']&&hash_equals($row['email_hash'],hash('sha256',strtolower($participant['email']))))return true;
    az_remember_revoke102((int)$participant['id']);return false;
}

/** Restore without resending an OTP. The current account state is always checked. */
function az_participant_restore102(): ?array {
    static $attempted=false;
    if($attempted||PHP_SAPI==='cli'||headers_sent())return null;
    $attempted=true;$parts=az_remember_parts102();
    if(!$parts){if(isset($_COOKIE[az_remember_name102()]))az_remember_cookie102('',time()-3600);return null;}
    [$selector,$validator]=$parts;$hash=hash('sha256',$validator);$db=cms_db();$now=time();$replacement=null;
    $db->beginTransaction();
    try{
        az_lock($db);
        $query=$db->prepare('SELECT r.*,p.email,p.name,p.phone,p.profile_completed,p.email_verified,p.active,p.session_version AS current_version FROM az_remember_tokens102 r JOIN az_participants p ON p.id=r.participant_id WHERE r.selector=?');
        $query->execute([$selector]);$row=$query->fetch();
        if(!$row||(int)$row['expires_at']<=$now||!$row['active']||(int)$row['session_version']!==(int)$row['current_version']||!hash_equals($row['email_hash'],hash('sha256',strtolower($row['email'])))){
            if($row)$db->prepare('DELETE FROM az_remember_tokens102 WHERE selector=?')->execute([$selector]);
            $db->commit();az_remember_cookie102('',time()-3600);return null;
        }
        $current=hash_equals($row['validator_hash'],$hash);
        $previous=!$current&&(int)$row['previous_until']>$now&&is_string($row['previous_hash'])&&hash_equals($row['previous_hash'],$hash);
        if(!$current&&!$previous){$db->commit();az_remember_cookie102('',time()-3600);return null;}
        if($current&&(int)$row['previous_until']<=$now){
            // Keep the same replacement during the grace period so rapid restores
            // cannot invalidate a parallel tab's previous token generation.
            $replacement=bin2hex(random_bytes(32));
            $db->prepare('UPDATE az_remember_tokens102 SET previous_hash=validator_hash,previous_until=?,validator_hash=?,last_used_at=? WHERE selector=?')->execute([$now+60,hash('sha256',$replacement),$now,$selector]);
        }else{$db->prepare('UPDATE az_remember_tokens102 SET last_used_at=? WHERE selector=?')->execute([$now,$selector]);}
        $db->commit();
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
    session_regenerate_id(true);
    $participant=['id'=>(int)$row['participant_id'],'email'=>$row['email'],'name'=>$row['name'],'phone'=>$row['phone'],'profile_completed'=>$row['profile_completed'],'email_verified'=>$row['email_verified'],'active'=>$row['active'],'session_version'=>(int)$row['current_version']];
    $_SESSION['participant_id']=$participant['id'];$_SESSION['participant_version']=$participant['session_version'];$_SESSION['participant_email']=strtolower($participant['email']);$_SESSION['participant_method']=$row['auth_method'];$_SESSION['participant_remember102']=$selector;
    if($replacement!==null)az_remember_cookie102($selector.'.'.$replacement,(int)$row['expires_at']);
    az_auth_event('login','remember_cookie',$participant);
    return $participant;
}
