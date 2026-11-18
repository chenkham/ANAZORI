<?php
declare(strict_types=1);
function az_install_participant_profile(PDO $db): void {
 if($db->query("SELECT value FROM cms_settings WHERE setting_key='participant_profile_schema'")->fetchColumn())return;
 $sqlite=$db->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite';
 $columns=$sqlite?array_column($db->query('PRAGMA table_info(az_participants)')->fetchAll(),'name'):array_column($db->query('SHOW COLUMNS FROM az_participants')->fetchAll(),'Field');
 foreach(['phone'=>"VARCHAR(25) NOT NULL DEFAULT ''",'profile_completed'=>'INT NOT NULL DEFAULT 0'] as $name=>$definition)if(!in_array($name,$columns,true))$db->exec('ALTER TABLE az_participants ADD COLUMN '.$name.' '.$definition);
 // Password signup already collects the person's own name. Existing Google names need confirmation.
 $db->exec("UPDATE az_participants SET profile_completed=1 WHERE google_sub IS NULL AND LENGTH(TRIM(name))>=2");
 cms_put_setting('participant_profile_schema','1');
}
function az_participant_destination(array $participant,string $next): string {
 $next=az_safe_next($next);
 if(!empty($participant['profile_completed']))return $next;
 $_SESSION['profile_next']=$next;return '/profile.php';
}
function az_update_participant_profile(array $participant,array $values): array {
 if((int)$participant['id']!==(int)($_SESSION['participant_id']??0))throw new RuntimeException('Sign in to edit your own profile.');
 $name=$values['name']??'';$phone=$values['phone']??'';
 if(!is_string($name)||mb_strlen(trim($name))<2||mb_strlen($name)>100||preg_match('/[<>\x00-\x1F]/u',$name))throw new InvalidArgumentException('Enter your full name using 2–100 characters.');
 if(!is_string($phone)||strlen($phone)>25)throw new InvalidArgumentException('Enter a valid phone number, or leave it blank.');
 $phone=trim($phone);$digits=preg_replace('/\D/','',$phone);
 if($phone!==''&&(!preg_match('/^\+?[0-9 ()-]{7,25}$/D',$phone)||strlen($digits)<7||strlen($digits)>15))throw new InvalidArgumentException('Enter a valid phone number, or leave it blank.');
 $name=trim($name);$phone=trim($phone);$db=cms_db();$db->beginTransaction();
 try{
  az_lock($db);$query=$db->prepare('SELECT * FROM az_participants WHERE id=?');$query->execute([$participant['id']]);$current=$query->fetch();
  if(!$current||!$current['active']||(int)$current['session_version']!==(int)($_SESSION['participant_version']??-1)||strtolower($current['email'])!==($_SESSION['participant_email']??''))throw new RuntimeException('Your session expired. Sign in again.');
  $db->prepare('UPDATE az_participants SET name=?,phone=?,profile_completed=1 WHERE id=?')->execute([$name,$phone,$current['id']]);
  $current['name']=$name;$current['phone']=$phone;$current['profile_completed']=1;
  az_notify_welcome89($current);
  az_auth_event('profile_updated',($_SESSION['participant_method']??'')==='google'?'google':'email_password',$current);
  $db->commit();return $current;
 }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
}
