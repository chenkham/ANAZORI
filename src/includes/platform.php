<?php
declare(strict_types=1);
const ANAZORI_SUPER_EMAIL='chenkhamchowlu@gmail.com';
require_once __DIR__.'/../vendor/autoload.php';
require_once __DIR__.'/mail-notifications.php';
require_once __DIR__.'/mail-transport95.php';
require_once __DIR__.'/private-storage.php';
require_once __DIR__.'/participant-remember102.php';
function az_install(PDO $db): void {
 $sqlite=$db->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite';$id=$sqlite?'INTEGER PRIMARY KEY AUTOINCREMENT':'INT AUTO_INCREMENT PRIMARY KEY';$text=$sqlite?'TEXT':'MEDIUMTEXT';
 $tables=[
  "az_participants (id $id,email VARCHAR(254) NOT NULL UNIQUE,name VARCHAR(100) NOT NULL,password_hash VARCHAR(255),google_sub VARCHAR(255) UNIQUE,email_verified INT NOT NULL DEFAULT 0,active INT NOT NULL DEFAULT 1,session_version INT NOT NULL DEFAULT 0,created_at VARCHAR(40) NOT NULL)",
  "az_challenges (id VARCHAR(64) PRIMARY KEY,kind VARCHAR(30) NOT NULL,user_kind VARCHAR(20) NOT NULL,user_id INT NOT NULL,email_hash VARCHAR(64) NOT NULL,code_hash VARCHAR(64) NOT NULL,expires_at BIGINT NOT NULL,attempts INT NOT NULL DEFAULT 0,consumed INT NOT NULL DEFAULT 0,created_at BIGINT NOT NULL)",
  "az_rate_limits (rate_key VARCHAR(64) PRIMARY KEY,attempts INT NOT NULL,expires_at BIGINT NOT NULL)",
  "az_orders (id $id,public_id VARCHAR(40) NOT NULL UNIQUE,participant_id INT NOT NULL,event_id INT NOT NULL,event_slug VARCHAR(100) NOT NULL,ticket_type VARCHAR(60) NOT NULL,snapshot $text NOT NULL,answers $text NOT NULL,quantity INT NOT NULL,unit_price INT NOT NULL,amount INT NOT NULL,currency VARCHAR(3) NOT NULL DEFAULT 'INR',state VARCHAR(30) NOT NULL,environment VARCHAR(10) NOT NULL,gateway_order VARCHAR(100) UNIQUE,gateway_payment VARCHAR(100) UNIQUE,provider_state VARCHAR(30),expires_at BIGINT NOT NULL,created_at VARCHAR(40) NOT NULL,updated_at VARCHAR(40) NOT NULL)",
  "az_tickets (id $id,ticket_id VARCHAR(40) NOT NULL UNIQUE,order_id INT NOT NULL,participant_id INT NOT NULL,event_id INT NOT NULL,token VARCHAR(140) NOT NULL UNIQUE,status VARCHAR(20) NOT NULL DEFAULT 'VALID',checked_at VARCHAR(40),checked_by INT,created_at VARCHAR(40) NOT NULL)",
  "az_checkins (id $id,ticket_id INT NOT NULL UNIQUE,staff_id INT NOT NULL,checked_at VARCHAR(40) NOT NULL)",
  "az_webhooks (event_id VARCHAR(150) PRIMARY KEY,received_at VARCHAR(40) NOT NULL)",
 ];foreach($tables as $table)$db->exec('CREATE TABLE IF NOT EXISTS '.$table);
 // Keep existing gateway references intact when adopting PhonePe for new orders.
 $orderColumns=$sqlite?array_column($db->query('PRAGMA table_info(az_orders)')->fetchAll(),'name'):array_column($db->query('SHOW COLUMNS FROM az_orders')->fetchAll(),'Field');
 foreach(['provider'=>"VARCHAR(20) NOT NULL DEFAULT 'razorpay'",'checkout_url'=>$text] as $name=>$definition)if(!in_array($name,$orderColumns,true))$db->exec("ALTER TABLE az_orders ADD COLUMN $name $definition");
 $db->exec("CREATE TABLE IF NOT EXISTS az_refunds (refund_id VARCHAR(100) PRIMARY KEY,order_id INT NOT NULL,amount INT NOT NULL,received_at VARCHAR(40) NOT NULL)");
 if(!$db->query("SELECT value FROM cms_settings WHERE setting_key='platform_schema'")->fetchColumn()){
  $columns=$sqlite?array_column($db->query('PRAGMA table_info(users)')->fetchAll(),'name'):array_column($db->query('SHOW COLUMNS FROM users')->fetchAll(),'Field');
  foreach(['permissions'=>'TEXT','staff_title'=>"VARCHAR(100) NOT NULL DEFAULT ''"] as $name=>$def)if(!in_array($name,$columns,true))$db->exec("ALTER TABLE users ADD COLUMN $name $def");
  $db->beginTransaction();try{
   $s=$db->prepare("SELECT * FROM users WHERE LOWER(email)=? OR LOWER(username)=? ORDER BY id LIMIT 1");$s->execute([ANAZORI_SUPER_EMAIL,ANAZORI_SUPER_EMAIL]);$master=$s->fetch();
   if(!$master)$master=$db->query("SELECT * FROM users WHERE role='OWNER' ORDER BY id LIMIT 1")->fetch();
   if($master){$s=$db->prepare("UPDATE users SET username=?,email=?,role='SUPERADMIN',active=1,must_change_password=1,session_version=session_version+1 WHERE id=?");$s->execute([ANAZORI_SUPER_EMAIL,ANAZORI_SUPER_EMAIL,$master['id']]);$masterId=$master['id'];}
   else{$s=$db->prepare("INSERT INTO users(username,email,password_hash,role,active,must_change_password) VALUES(?,?,?,'SUPERADMIN',1,0)");$s->execute([ANAZORI_SUPER_EMAIL,ANAZORI_SUPER_EMAIL,password_hash(bin2hex(random_bytes(32)),PASSWORD_DEFAULT)]);$masterId=$db->lastInsertId();}
   $s=$db->prepare("UPDATE users SET role='ADMIN',session_version=session_version+1 WHERE role IN ('OWNER','SUPERADMIN') AND id<>?");$s->execute([$masterId]);
   cms_put_setting('platform_schema','1');$db->commit();
 }catch(Throwable $e){if($db->inTransaction())$db->rollBack();throw $e;}
 }
 if(!$db->query("SELECT value FROM cms_settings WHERE setting_key='platform_indexes'")->fetchColumn()){
  foreach(['az_orders_participant'=>'az_orders (participant_id,id)','az_orders_capacity'=>'az_orders (event_id,ticket_type,environment,state,expires_at)','az_tickets_order'=>'az_tickets (order_id)','az_tickets_participant'=>'az_tickets (participant_id)','az_challenges_user'=>'az_challenges (user_kind,user_id,kind)'] as $name=>$definition){try{$db->exec('CREATE INDEX '.($sqlite?'IF NOT EXISTS ':'').$name.' ON '.$definition);}catch(PDOException $e){if((int)($e->errorInfo[1]??0)!==1061)throw $e;}}
  cms_put_setting('platform_indexes','1');
 }
}
function az_is_super(array $u): bool {return $u['role']==='SUPERADMIN'&&strtolower($u['email']??'')===ANAZORI_SUPER_EMAIL&&strtolower($u['username'])===ANAZORI_SUPER_EMAIL;}
function az_permission_labels(): array {
 $out=[];foreach(cms_content_schema() as $module=>$schema)foreach(['view'=>'View','edit'=>'Create / edit','publish'=>'Publish','delete'=>'Remove'] as $action=>$label)$out[$module.'.'.$action]=$label.' '.strtolower($schema['label']);
 return $out+['media.view'=>'View media library','media.edit'=>'Upload files','media.delete'=>'Remove unused media','settings.edit'=>'Manage website settings','participants.view'=>'View participants','participants.edit'=>'Enable / disable shared participant accounts (festival-wide)','payments.view'=>'View orders and payments','payments.verify'=>'Review screenshots and confirm event payments','tickets.view'=>'View issued tickets','tickets.revoke'=>'Block / unblock or revoke tickets','tickets.scan'=>'Scan and check in assigned event tickets','submissions.view'=>'View interest / legacy applications','submissions.edit'=>'Review interest / legacy applications','audit.view'=>'View activity log','operations.export'=>'Export assigned event registrations, orders and attendance'];
}
function az_key(): string {static $key;if($key)return $key;$environment=getenv('ANAZORI_APP_KEY');if($environment){$key=base64_decode($environment,true);if(strlen($key?:'')!==32)throw new RuntimeException('ANAZORI_APP_KEY must encode 32 random bytes.');return $key;}
 $path=az_application_key_path90();if(!is_dir(dirname($path)))az_private_directory90(dirname($path));
 if(!is_file($path)){$f=@fopen($path,'x');if($f){fwrite($f,base64_encode(random_bytes(32)));fclose($f);@chmod($path,0600);}}
 $key=base64_decode(trim(file_get_contents($path)),true);if(strlen($key?:'')!==32)throw new RuntimeException('Application encryption key is unavailable.');return $key;
}
function az_encrypt(string $value): string {$iv=random_bytes(12);$cipher=openssl_encrypt($value,'aes-256-gcm',az_key(),OPENSSL_RAW_DATA,$iv,$tag);return base64_encode($iv.$tag.$cipher);}
function az_decrypt(string $value): string {$raw=base64_decode($value,true);if(!$raw||strlen($raw)<28)throw new RuntimeException('Invalid integration settings.');$plain=openssl_decrypt(substr($raw,28),'aes-256-gcm',az_key(),OPENSSL_RAW_DATA,substr($raw,0,12),substr($raw,12,16));if($plain===false)throw new RuntimeException('Integration settings could not be decrypted. Restore the application key.');return $plain;}
function az_config(): array {
 $s=cms_db()->query("SELECT value FROM cms_settings WHERE setting_key='integrations_private'")->fetchColumn();$data=$s?json_decode(az_decrypt($s),true):[];
 $defaults=['site_url'=>'','smtp_host'=>'smtp.hostinger.com','smtp_port'=>'465','smtp_security'=>'ssl','smtp_user'=>ANAZORI_MAILBOX,'smtp_password'=>'','smtp_from'=>ANAZORI_MAILBOX,'google_client_id'=>'','google_client_secret'=>'','payment_enabled'=>'0','payment_mode'=>'test','razorpay_key_id'=>'','razorpay_key_secret'=>'','razorpay_webhook_secret'=>''];
 foreach($defaults as $key=>$value){$override=getenv('ANAZORI_'.strtoupper($key));if($override!==false)$data[$key]=$override;}
 $data=array_replace($defaults,$data?:[]);
 // Legacy SMTP fields remain readable for old settings screens; delivery uses PHP mail().
 $data['smtp_user']=ANAZORI_MAILBOX;$data['smtp_from']=ANAZORI_MAILBOX;
 $environment=getenv('ANAZORI_PHONEPE_ENV');
 if($environment!==false){$data['payment_mode']=match($environment){'sandbox'=>'test','production'=>'live',default=>'invalid'};}
 $prefix=$data['payment_mode']==='live'?'ANAZORI_PHONEPE_PRODUCTION_':'ANAZORI_PHONEPE_SANDBOX_';
 foreach(['client_id','client_version','client_secret','webhook_username','webhook_password'] as $name){
  $value=getenv($prefix.strtoupper($name));
  if($value===false)$value=getenv('ANAZORI_PHONEPE_'.strtoupper($name));
  // PhonePe credentials are environment-only, never read from editable CMS data.
  $data['phonepe_'.$name]=$value===false?'':$value;
 }
 return $data;
}
function az_origin(): string {$host=$_SERVER['HTTP_HOST']??'';if(APP_ENV==='development'&&preg_match('/^(localhost|127\.0\.0\.1)(:\d+)?$/D',$host))return 'http://'.$host;$url=rtrim(az_config()['site_url'],'/');if($url)return $url;$host=$_SERVER['HTTP_HOST']??'127.0.0.1:8088';if(!preg_match('/^(localhost|127\.0\.0\.1)(:\d+)?$/',$host))throw new RuntimeException('Set the public website URL in Integrations.');return 'http://'.$host;}
function az_mail_ready(): bool {return function_exists('mail');}
function az_mail_delivery_available(): bool {return getenv('ANAZORI_TEST_MODE')==='1'?is_dir(getenv('ANAZORI_TEST_OUTBOX')?:''):az_mail_ready();}
function az_google_ready(): bool {$c=az_config();return $c['google_client_id']!==''&&$c['google_client_secret']!==''&&$c['site_url']!=='';}
function az_payment_ready(): bool {$c=az_config();return $c['payment_enabled']==='1'&&az_phonepe_configured($c);}
function az_phonepe_configured(array $c): bool {return in_array($c['payment_mode'],['test','live'],true)&&$c['phonepe_client_id']!==''&&ctype_digit($c['phonepe_client_version'])&&$c['phonepe_client_secret']!==''&&$c['phonepe_webhook_username']!==''&&$c['phonepe_webhook_password']!=='';}
function az_lock(PDO $db): void {$db->exec("UPDATE cms_settings SET value=value WHERE setting_key='platform_schema'");}
function az_limit(string $scope,string $identity,int $max,int $window): void {
 $db=cms_db();$key=hash_hmac('sha256',$scope.'|'.$identity,az_key());$now=time();$db->beginTransaction();try{az_lock($db);$s=$db->prepare('SELECT * FROM az_rate_limits WHERE rate_key=?');$s->execute([$key]);$r=$s->fetch();
  if($r&&$r['expires_at']>$now&&$r['attempts']>=$max)throw new RuntimeException('Too many attempts. Please wait before trying again.');
  if(!$r){$s=$db->prepare('INSERT INTO az_rate_limits(rate_key,attempts,expires_at) VALUES(?,1,?)');$s->execute([$key,$now+$window]);}else{$s=$db->prepare('UPDATE az_rate_limits SET attempts=?,expires_at=? WHERE rate_key=?');$s->execute([$r['expires_at']>$now?$r['attempts']+1:1,$r['expires_at']>$now?$r['expires_at']:$now+$window,$key]);}$db->commit();
 }catch(Throwable $e){if($db->inTransaction())$db->rollBack();throw $e;}
}
function az_auth_limit(string $scope,string $email,int $max=8,int $window=900): void {az_limit($scope.'.ip',$_SERVER['REMOTE_ADDR']??'cli',$max*3,$window);az_limit($scope.'.email',strtolower($email),$max,$window);}
function az_send_mail(string $email,string $subject,string $body,string $html='',bool $priority=true): void {
 if(!$priority&&!az_mail_notifications_enabled89())return;
 try{az_mail_deliver95($priority?'otp':'notice',$email,$subject,$body,$html);}
 finally{try{az_mail_flush_alerts95();}catch(Throwable $e){error_log('ANAZORI mail alert remains queued.');}}
}
function az_otp_start(string $kind,string $userKind,int $userId,string $email): string {
 az_auth_limit('otp.send.'.$kind,$email,5,3600);az_limit('otp.cooldown',$email,1,60);$id=bin2hex(random_bytes(24));$code=(string)random_int(100000,999999);$hash=hash_hmac('sha256',$id.'|'.$code,az_key());
 $message=az_mail_template($kind==='VERIFY'?'verify':'reset',['code'=>$code]);
 az_send_mail($email,$message['subject'],$message['body'],$message['html']);$issuedAt=time();
 $db=cms_db();$db->beginTransaction();try{az_lock($db);$s=$db->prepare('UPDATE az_challenges SET consumed=1 WHERE kind=? AND user_kind=? AND user_id=?');$s->execute([$kind,$userKind,$userId]);$s=$db->prepare('INSERT INTO az_challenges(id,kind,user_kind,user_id,email_hash,code_hash,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)');$s->execute([$id,$kind,$userKind,$userId,hash('sha256',strtolower($email)),$hash,$issuedAt+600,$issuedAt]);$db->commit();}catch(Throwable $e){if($db->inTransaction())$db->rollBack();throw $e;}
 az_auth_event('otp_sent','email_otp',['id'=>$userId,'email'=>$email],$userKind);
 $_SESSION['az_challenges'][$id]=true;return $id;
}
function az_otp_consume(string $id,string $code,string $kind,callable $after): void {
 if(!isset($_SESSION['az_challenges'][$id])||!preg_match('/^\d{6}$/',$code))throw new RuntimeException('The verification code is invalid or expired.');
 $db=cms_db();$db->beginTransaction();try{az_lock($db);$s=$db->prepare('SELECT * FROM az_challenges WHERE id=?');$s->execute([$id]);$r=$s->fetch();
  if(!$r||$r['kind']!==$kind||$r['consumed']||$r['expires_at']<=time()||$r['attempts']>=5)throw new RuntimeException('The verification code is invalid or expired.');
  if(!hash_equals($r['code_hash'],hash_hmac('sha256',$id.'|'.$code,az_key()))){$db->prepare('UPDATE az_challenges SET attempts=attempts+1 WHERE id=?')->execute([$id]);$db->commit();az_auth_event('otp_failed','email_otp',['id'=>$r['user_id']],$r['user_kind'],false);throw new RuntimeException('The verification code is invalid or expired.');}
  $after($db,$r);$db->prepare('UPDATE az_challenges SET consumed=1 WHERE id=?')->execute([$id]);$db->commit();unset($_SESSION['az_challenges'][$id]);
 }catch(Throwable $e){if($db->inTransaction())$db->rollBack();throw $e;}
}
function az_participant(): ?array {
 if(empty($_SESSION['participant_id'])){$restored=az_participant_restore102();if($restored&&!headers_sent())header('Cache-Control: private, no-store');return $restored;}
 $s=cms_db()->prepare('SELECT id,email,name,phone,profile_completed,email_verified,active,session_version FROM az_participants WHERE id=?');$s->execute([$_SESSION['participant_id']]);$u=$s->fetch();
 if(!$u||!$u['active']||(int)$u['session_version']!==(int)($_SESSION['participant_version']??-1)||strtolower($u['email'])!==($_SESSION['participant_email']??'')){az_remember_revoke102((int)$_SESSION['participant_id']);az_participant_clear102();return null;}
 if(!az_remember_session_current102($u)){az_participant_clear102();return null;}
 if(!headers_sent())header('Cache-Control: private, no-store');return $u;
}
function az_participant_login(array $u,string $method='email_password',string $event='login'): void {
 $query=cms_db()->prepare('SELECT * FROM az_participants WHERE id=?');$query->execute([$u['id']]);$stored=$query->fetch();
 if(!$stored||!$stored['active']||strtolower($stored['email'])!==strtolower($u['email'])||(int)$stored['session_version']!==(int)$u['session_version'])throw new RuntimeException('This account is unavailable.');
 if(!empty($_SESSION['participant_id'])&&(int)$_SESSION['participant_id']!==(int)$stored['id']){az_remember_revoke102();az_participant_clear102();}
 $u=$stored;$_SESSION['participant_email']=strtolower($u['email']);az_auth_event($event,$method,$u);$_SESSION['participant_method']=$method;
 session_regenerate_id(true);$_SESSION['participant_id']=$u['id'];$_SESSION['participant_version']=(int)$u['session_version'];az_remember_issue102($u,$method);
}
function az_require_participant(bool $verified=false,bool $complete=true): array {$u=az_participant();if(!$u){header('Location: /account.php?next='.rawurlencode(az_safe_next($_SERVER['REQUEST_URI']??'/dashboard.php')));exit;}if($complete&&empty($u['profile_completed'])){header('Location: '.az_participant_destination($u,$_SERVER['REQUEST_URI']??'/dashboard.php'));exit;}if($verified&&!$u['email_verified']){$_SESSION['participant_next']=az_safe_next($_SERVER['REQUEST_URI']??'/dashboard.php');header('Location: /verify-email.php');exit;}return $u;}
function az_safe_next(string $path): string {if($path==='/#motion-studio')return $path;return preg_match('#^/(?:dashboard\.php|profile\.php|checkout\.php(?:\?event=[a-z0-9-]+)?|event\.php\?name=[a-z0-9-]+|payment-return\.php\?order=ORDER-[A-F0-9]{16})$#',$path)?$path:'/dashboard.php';}
function az_password(string $password): void {if(strlen($password)<12||strlen($password)>200)throw new InvalidArgumentException('Use a password of 12–200 characters.');}
function az_csrf(): void {if(!is_string($_POST['csrf_token']??null)||!csrf_verify($_POST['csrf_token']))throw new RuntimeException('Your session expired. Reload and try again.');}
function az_staff_login(array $u,string $method='email_password'): void {
 if(!$u['active']||!in_array($u['role'],['SUPERADMIN','ADMIN','FACULTY','COORDINATOR','EDITOR','VOLUNTEER'],true)||($u['role']==='SUPERADMIN'&&!az_is_super($u)))throw new RuntimeException('This staff account is unavailable.');
 az_auth_event('login',$method,$u,'staff');$_SESSION['staff_method']=$method;
 session_regenerate_id(true);$_SESSION['admin_logged_in']=true;$_SESSION['admin_id']=$u['id'];$_SESSION['admin_username']=$u['username'];$_SESSION['admin_role']=$u['role'];$_SESSION['admin_version']=(int)$u['session_version'];cms_audit($u,'account.login','Successful sign-in');
}
function az_money(int $paise): string {return '₹'.number_format($paise/100,2);}
function az_social_icon(string $key): string {
 $paths=['instagram'=>'<rect x="3" y="3" width="18" height="18" rx="5"/><circle cx="12" cy="12" r="4"/><circle cx="17.5" cy="6.5" r=".7" fill="currentColor"/>','facebook'=>'<path fill="currentColor" stroke="none" d="M14 22v-9h3l.5-4H14V6.5c0-1 .3-1.5 1.6-1.5H18V1.4A23 23 0 0 0 14.8 1C11.6 1 10 3 10 6v3H7v4h3v9z"/>','institution_url'=>'<path d="m2 9 10-6 10 6-10 6zM5 11v7c4 3 10 3 14 0v-7M22 9v9"/>'];return '<svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'.($paths[$key]??$paths['institution_url']).'</svg>';
}
function az_save_integrations(): void {
 $c=az_config();$url=cms_text('site_url',500);if(!filter_var($url,FILTER_VALIDATE_URL)||parse_url($url,PHP_URL_QUERY)||parse_url($url,PHP_URL_USER)||parse_url($url,PHP_URL_FRAGMENT)||!(parse_url($url,PHP_URL_SCHEME)==='https'||(parse_url($url,PHP_URL_SCHEME)==='http'&&in_array(parse_url($url,PHP_URL_HOST),['localhost','127.0.0.1'],true))))throw new RuntimeException('Use the HTTPS public website URL, or a localhost URL for testing.');$c['site_url']=rtrim($url,'/');
 $c['google_client_id']=cms_text('google_client_id',500);
 $secret=cms_text('google_client_secret',500);if($secret!=='')$c['google_client_secret']=$secret;
 if(!array_key_exists('payment_mode',$_POST)){cms_put_setting('integrations_private',az_encrypt(json_encode($c,JSON_THROW_ON_ERROR)));return;}
 $mode=cms_text('payment_mode',10);if(!in_array($mode,['test','live'],true))throw new RuntimeException('Choose test or live payments.');
 if((getenv('ANAZORI_PHONEPE_ENV')!==false||getenv('ANAZORI_PAYMENT_MODE')!==false)&&$mode!==$c['payment_mode'])throw new RuntimeException('Payment environment is controlled by the hosting environment.');
 $c['payment_mode']=$mode;$c['payment_enabled']=isset($_POST['payment_enabled'])?'1':'0';
 // Resolve credentials again for the newly selected environment before enabling it.
 $prefix=$mode==='live'?'ANAZORI_PHONEPE_PRODUCTION_':'ANAZORI_PHONEPE_SANDBOX_';
 foreach(['client_id','client_version','client_secret','webhook_username','webhook_password'] as $name){$value=getenv($prefix.strtoupper($name));if($value===false)$value=getenv('ANAZORI_PHONEPE_'.strtoupper($name));$c['phonepe_'.$name]=$value===false?'':$value;}
 if($c['payment_enabled']==='1'&&!az_phonepe_configured($c))throw new RuntimeException('Configure PhonePe API and SHA webhook credentials in the hosting environment before enabling checkout.');
 foreach(array_keys($c) as $key)if(str_starts_with($key,'phonepe_'))unset($c[$key]);
 cms_put_setting('integrations_private',az_encrypt(json_encode($c,JSON_THROW_ON_ERROR)));
}
function az_http(string $url,string $method='GET',?array $body=null,?array $basic=null,array $headers=[]): array {
 $c=curl_init($url);curl_setopt_array($c,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>20,CURLOPT_CONNECTTIMEOUT=>8,CURLOPT_FOLLOWLOCATION=>false,CURLOPT_PROTOCOLS=>CURLPROTO_HTTPS|((getenv('ANAZORI_TEST_MODE')==='1')?CURLPROTO_HTTP:0),CURLOPT_HTTPHEADER=>$headers]);
 if($basic)curl_setopt($c,CURLOPT_USERPWD,$basic[0].':'.$basic[1]);if($method==='POST'){curl_setopt($c,CURLOPT_POST,true);curl_setopt($c,CURLOPT_POSTFIELDS,$body?json_encode($body):'');}if($method==='FORM'){curl_setopt($c,CURLOPT_POST,true);curl_setopt($c,CURLOPT_POSTFIELDS,http_build_query($body??[]));}
 $raw=curl_exec($c);$status=curl_getinfo($c,CURLINFO_RESPONSE_CODE);curl_close($c);$data=json_decode($raw?:'',true);if($status<200||$status>=300||!is_array($data))throw new RuntimeException('The service did not respond successfully. Please try again.');return $data;
}
