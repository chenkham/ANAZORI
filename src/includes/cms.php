<?php
declare(strict_types=1);
require_once __DIR__.'/../config/db.php';
require_once __DIR__.'/../config/security.php';
require_once __DIR__.'/cms-schema.php';
require_once __DIR__.'/brand.php';
require_once __DIR__.'/responsive-images84.php';
require_once __DIR__.'/platform.php';
require_once __DIR__.'/auth-history.php';
require_once __DIR__.'/participant-profile.php';
require_once __DIR__.'/studio-access.php';
require_once __DIR__.'/studio-coordinator-workflow.php';
require_once __DIR__.'/studio-finance.php';
require_once __DIR__.'/registration-forms.php';
require_once __DIR__.'/game-categories.php';
require_once __DIR__.'/manual-payments.php';
require_once __DIR__.'/manual-finance.php';
require_once __DIR__.'/release-updates.php';
require_once __DIR__.'/brochure-update63.php';
require_once __DIR__.'/event-participation.php';
require_once __DIR__.'/certificates.php';
require_once __DIR__.'/registration-progress79.php';
require_once __DIR__.'/event-options81.php';
function cms_db(): PDO {
 static $ready=false;$db=Database::getConnection();if($ready)return $db;$ready=true;
 $sqlite=$db->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite';$id=$sqlite?'INTEGER PRIMARY KEY AUTOINCREMENT':'INT AUTO_INCREMENT PRIMARY KEY';$text=$sqlite?'TEXT':'MEDIUMTEXT';
 $db->exec("CREATE TABLE IF NOT EXISTS cms_settings (setting_key VARCHAR(100) PRIMARY KEY, value $text NOT NULL)");
 $db->exec("CREATE TABLE IF NOT EXISTS cms_content (id $id, type VARCHAR(30) NOT NULL, slug VARCHAR(100) NOT NULL, title VARCHAR(255) NOT NULL, data $text NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'DRAFT', sort_order INT NOT NULL DEFAULT 0, created_by INT NOT NULL DEFAULT 0, revision INT NOT NULL DEFAULT 1, updated_at VARCHAR(40) NOT NULL, UNIQUE(type,slug))");
 $db->exec("CREATE TABLE IF NOT EXISTS cms_media (id $id, path VARCHAR(255) NOT NULL UNIQUE, title VARCHAR(255) NOT NULL, mime VARCHAR(100) NOT NULL, size_bytes INT NOT NULL DEFAULT 0, uploaded_by INT NOT NULL DEFAULT 0, created_at VARCHAR(40) NOT NULL)");
 $db->exec("CREATE TABLE IF NOT EXISTS cms_audit (id $id, user_id INT NOT NULL, username VARCHAR(100) NOT NULL, action VARCHAR(100) NOT NULL, detail $text NOT NULL, created_at VARCHAR(40) NOT NULL)");
 $db->exec("CREATE TABLE IF NOT EXISTS cms_login_attempts (attempt_key VARCHAR(100) PRIMARY KEY, attempts INT NOT NULL, expires_at INT NOT NULL)");
 $schema=$db->query("SELECT value FROM cms_settings WHERE setting_key='schema_version'")->fetchColumn();
 if(!$schema){
  $columns=$sqlite?array_column($db->query('PRAGMA table_info(users)')->fetchAll(),'name'):array_column($db->query('SHOW COLUMNS FROM users')->fetchAll(),'Field');
  foreach(['active'=>'INT NOT NULL DEFAULT 1','display_name'=>"VARCHAR(150) NOT NULL DEFAULT ''",'email'=>"VARCHAR(254) NOT NULL DEFAULT ''",'modules'=>'TEXT','session_version'=>'INT NOT NULL DEFAULT 0','must_change_password'=>'INT NOT NULL DEFAULT 0'] as $name=>$def)if(!in_array($name,$columns,true))$db->exec("ALTER TABLE users ADD COLUMN $name $def");
  $db->exec("UPDATE users SET role='OWNER' WHERE role='ADMIN'");
  foreach($db->query('SELECT id,password_hash FROM users') as $u)if(password_verify(DEFAULT_ADMIN_PASS,$u['password_hash'])){$s=$db->prepare('UPDATE users SET must_change_password=1 WHERE id=?');$s->execute([$u['id']]);}
  cms_put_setting('schema_version','1');
 }
 if(!$db->query("SELECT value FROM cms_settings WHERE setting_key='seeded'")->fetchColumn()){require __DIR__.'/cms-seed.php';cms_seed($db);}
 az_install($db);
 az_install_auth_history($db);
 az_install_participant_profile($db);
 az_install_remember102($db);
 st_install_access($db);
 st_install_finance($db);
 az_install_manual_payments($db);
 az_install_manual_finance($db);
 az_apply_programme_updates($db);
 az_clean_public_seed($db);
 az_apply_launch_updates($db);
 st_install_coordinator_workflow($db);
 az_move_home_film($db);
 az_apply_brochure63($db);
 az_install_participation66($db);
 az_install_form_storage($db);
 az_install_progress79($db);
 az_install_options81($db);
 az_install_autosave88($db);
 az_install_mail89($db);
 az_install_mail95($db);
 az_update_official_contact73($db);
 az_install_certificates($db);
 if(APP_ENV==='production'&&getenv('ANAZORI_TEST_MODE')!=='1'){az_key();az_storage_checks90();}
 return $db;
}
function cms_put_setting(string $key,string $value): void {
 $db=cms_db();$s=$db->prepare('SELECT setting_key FROM cms_settings WHERE setting_key=?');$s->execute([$key]);
 if($s->fetchColumn()){$s=$db->prepare('UPDATE cms_settings SET value=? WHERE setting_key=?');$s->execute([$value,$key]);}else{$s=$db->prepare('INSERT INTO cms_settings(setting_key,value) VALUES(?,?)');$s->execute([$key,$value]);}
}
function cms_settings(): array {static $value=null;if($value===null){$s=cms_db()->query("SELECT value FROM cms_settings WHERE setting_key='site'")->fetchColumn();$value=array_replace(cms_defaults(),json_decode($s?:'{}',true)?:[]);}return $value;}
function setting(string $key,string $fallback=''): string {return (string)(cms_settings()[$key]??$fallback);}
function cms_records(string $type,bool $published=true): array {$s=cms_db()->prepare('SELECT * FROM cms_content WHERE type=?'.($published?" AND status='PUBLISHED'":'').' ORDER BY sort_order,id');$s->execute([$type]);return array_map('cms_unpack',$s->fetchAll());}
function cms_unpack(array $row): array {
 // The schema is code-defined and constant during this request; records remain live database reads.
 static $schema=null;$schema??=cms_content_schema();
 $defaults=[];foreach($schema[$row['type']]['fields']??[] as $key=>$def)$defaults[$key]=$def[2]??'';
 $row['fields']=array_replace($defaults,json_decode($row['data'],true)?:[]);
 if($row['type']==='event')$row['fields']=az_participation_fields($row['slug'],$row['fields']);
 return $row;
}
function cms_record(int $id): ?array {$s=cms_db()->prepare('SELECT * FROM cms_content WHERE id=?');$s->execute([$id]);$r=$s->fetch();return $r?cms_unpack($r):null;}
function cms_user(): ?array {
 if(empty($_SESSION['admin_id'])||empty($_SESSION['admin_logged_in']))return null;
 $s=cms_db()->prepare('SELECT id,username,role,active,display_name,email,modules,permissions,staff_title,event_scope,session_version,must_change_password FROM users WHERE id=?');$s->execute([(int)$_SESSION['admin_id']]);$u=$s->fetch();
 if(!$u||!$u['active']||!in_array($u['role'],['SUPERADMIN','ADMIN','FACULTY','COORDINATOR','EDITOR','VOLUNTEER'],true)||(int)($_SESSION['admin_version']??0)!==(int)$u['session_version']){unset($_SESSION['admin_logged_in'],$_SESSION['admin_id']);return null;}return $u;
}
function cms_require_user(): array {$u=cms_user();if(!$u){header('Location: /login.php');exit;}return $u;}
function cms_can(array $u,string $module,string $action='view',?array $record=null): bool {
 if($module==='event'&&$record&&!st_can_event($u,(int)$record['id']))return false;
 if($module==='event'&&!$record&&$action!=='view'&&!st_has_global_access($u))return false;
 if(in_array($module,['budgets','expenses','reports'],true))$module='finance';
 if($module==='profile'||$module==='overview')return true;
 if(az_is_super($u))return true;
 if(in_array($module,['users','integrations'],true))return false;
 if($u['role']==='SUPERADMIN')return false;
 $p=json_decode($u['permissions']??'null',true);
 if(!is_array($p)){
  $p=[];$areas=json_decode($u['modules']??'null',true);
  if($u['role']==='ADMIN')$p=array_keys(az_permission_labels());
  else foreach(is_array($areas)?$areas:($u['role']==='EDITOR'?['event','gallery','person','sponsor','collaboration','faq','media']:['gallery','person','media']) as $area)foreach($u['role']==='EDITOR'?['view','edit','publish','delete']:['view','edit'] as $a)$p[]=$area.'.'.$a;
 }
 if($module==='logins')return st_has_global_access($u)&&in_array('participants.view',$p,true);
 if($module==='settings')return in_array('settings.edit',$p,true);
 if($module==='checkin')return in_array('tickets.scan',$p,true);
 if(!in_array($module.'.'.$action,$p,true))return false;
 if($u['role']==='VOLUNTEER'&&isset(cms_content_schema()[$module])){
  if(in_array($action,['publish','delete'],true))return false;
  if($record&&((int)$record['created_by']!==(int)$u['id']||$record['status']!=='DRAFT'))return false;
 }
 return true;
}
function cms_audit(array $u,string $action,string $detail): void {$s=cms_db()->prepare('INSERT INTO cms_audit(user_id,username,action,detail,created_at) VALUES(?,?,?,?,?)');$s->execute([$u['id'],$u['username'],$action,$detail,gmdate('c')]);}
function cms_slug(string $text): string {return trim(preg_replace('/[^a-z0-9]+/','-',strtolower($text)),'-');}
function cms_date(string $value): ?DateTimeImmutable {if(!$value)return null;$d=DateTimeImmutable::createFromFormat('!Y-m-d\TH:i',$value,new DateTimeZone('Asia/Kolkata'));return $d&&$d->format('Y-m-d\TH:i')===$value?$d:null;}
function cms_date_label(string $value): string {return cms_date($value)?->format('d M Y · g:i a').' '.($value?'IST':'');}
function cms_text(string $key,int $max=10000): string {$v=$_POST[$key]??'';if(!is_string($v)||mb_strlen($v)>$max||str_contains($v,"\0"))throw new InvalidArgumentException('Check the '.str_replace('_',' ',$key).' field.');return trim($v);}
function cms_validate_fields(array $schema): array {
 $data=[];foreach($schema as $key=>$def){
  if($key==='event_documents'){$rows=$_POST[$key]??(isset($_POST['event_documents_editor103'])?[]:'');$data[$key]=$rows===''?'':az_validate_event_documents103($rows);continue;}
  $type=$def[1];$v=$type==='checkbox'?(isset($_POST[$key])?'1':'0'):cms_text($key,$type==='textarea'?20000:($type==='text'?500:2048));
  if($key==='reminder_window'&&$v==='')$v='24h';
  if($v!==''&&$type==='url'&&(!filter_var($v,FILTER_VALIDATE_URL)||!in_array(strtolower(parse_url($v,PHP_URL_SCHEME)??''),['https','http'],true)))throw new InvalidArgumentException($def[0].' must be an http or https URL.');
  if($v!==''&&$type==='email'&&!filter_var($v,FILTER_VALIDATE_EMAIL))throw new InvalidArgumentException($def[0].' must be a valid email.');
  if($v!==''&&$type==='datetime-local'&&!cms_date($v))throw new InvalidArgumentException('Check '.$def[0].'.');
  if($type==='select'&&!array_key_exists($v,$def[3]))throw new InvalidArgumentException('Choose a valid '.$def[0].'.');
  if($type==='number'&&(!ctype_digit($v)||(int)$v<10||(int)$v>120))throw new InvalidArgumentException($def[0].' must be between 10 and 120.');
  if($type==='price'){require_once __DIR__.'/commerce.php';az_inr_to_paise($v);}
  if(in_array($type,['image','video','audio','pdf'],true)&&$v!==''&&!cms_valid_media($v,$type))throw new InvalidArgumentException('Choose an available '.$type.' for '.$def[0].'.');
  if($key==='registration_url')$v=az_google_form_url97($v);
  $data[$key]=$v;
 }
 if(!empty($data['starts_at'])&&!empty($data['ends_at'])&&cms_date($data['ends_at'])<=cms_date($data['starts_at']))throw new InvalidArgumentException('The end must be later than the start.');
 if(($data['registration_mode']??'')==='scheduled'&& (empty($data['registration_opens'])||empty($data['registration_closes'])))throw new InvalidArgumentException('Automatic registration needs both an opening and a closing date.');
 if(!empty($data['registration_opens'])&&!empty($data['registration_closes'])&&cms_date($data['registration_closes'])<=cms_date($data['registration_opens']))throw new InvalidArgumentException('Registration must close after it opens.');
 if(count(cms_questions($data))>12)throw new InvalidArgumentException('Use at most 12 extra registration questions.');
 return $data;
}
function cms_valid_media(string $path,string $kind): bool {
 $s=cms_db()->prepare('SELECT mime FROM cms_media WHERE path=?');$s->execute([$path]);$mime=$s->fetchColumn();return $mime&&($kind==='pdf'?$mime==='application/pdf':str_starts_with($mime,$kind.'/'));
}
function cms_media(?array $u=null): array {$s=cms_db()->prepare('SELECT * FROM cms_media'.($u&&$u['role']==='VOLUNTEER'?' WHERE uploaded_by=?':'').' ORDER BY id DESC');$s->execute($u&&$u['role']==='VOLUNTEER'?[$u['id']]:[]);return $s->fetchAll();}
function cms_upload(array $u,array $file): int {
 $u=st_refresh_user($u);
 if($u['must_change_password']||!cms_can($u,'media','edit'))throw new RuntimeException('You do not have upload access.');
 az_limit('media-upload',(string)$u['id'],30,900);
 $types=['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp','image/gif'=>'gif','application/pdf'=>'pdf','video/mp4'=>'mp4','audio/mpeg'=>'mp3','audio/mp4'=>'m4a','audio/x-wav'=>'wav','audio/wav'=>'wav'];
 $info=az_validate_upload95($file,$types,64*1024*1024);$mime=$info['mime'];
 $limit=str_starts_with($mime,'video/')||str_starts_with($mime,'audio/')?64*1024*1024:12*1024*1024;
 if($info['size']>$limit)throw new InvalidArgumentException('Images and PDFs must be below 12 MB; video and audio below 64 MB.');
 $dir=getenv('ANAZORI_MEDIA_DIR')?:__DIR__.'/../uploads/media';if(!is_dir($dir)&&!mkdir($dir,0755,true))throw new RuntimeException('Upload storage is unavailable.');
 $name=bin2hex(random_bytes(18)).'.'.$types[$mime];$path=$dir.'/'.$name;$moved=false;$db=cms_db();$db->beginTransaction();try{
  az_lock($db);$u=st_refresh_user($u);if($u['must_change_password']||!cms_can($u,'media','edit'))throw new RuntimeException('Your upload permission was revoked.');
  if(!move_uploaded_file($file['tmp_name'],$path))throw new RuntimeException('The file could not be stored.');$moved=true;
  $title=mb_substr(basename((string)$file['name']),0,180);$s=$db->prepare('INSERT INTO cms_media(path,title,mime,size_bytes,uploaded_by,created_at) VALUES(?,?,?,?,?,?)');$s->execute(['/uploads/media/'.$name,$title,$mime,$info['size'],$u['id'],gmdate('c')]);$id=(int)$db->lastInsertId();cms_audit($u,'media.upload',$title);$db->commit();try{az_generate_image_variants84('/uploads/media/'.$name);}catch(Throwable){/* An optional variant must never invalidate a saved upload. */}return $id;
 }catch(Throwable $error){if($db->inTransaction())$db->rollBack();if($moved&&is_file($path))@unlink($path);throw $error;}
}
function cms_questions(array $event): array {return array_values(array_filter(array_map('trim',preg_split('/\R/',$event['registration_questions']??''))));}
function cms_event_phase(array $event,?int $now=null): string {
 $phase=$event['registration_mode']??'interest';$now=$now??time();
 if($phase==='scheduled'){$open=cms_date($event['registration_opens']??'');$close=cms_date($event['registration_closes']??'');$end=cms_date($event['ends_at']??'');
  if($end&&$now>=$end->getTimestamp())return 'completed';
  if(!$open||!$close)return 'interest';
  return $now<$open->getTimestamp()?'interest':($now<$close->getTimestamp()?'open':'closed');
 }
 return in_array($phase,['interest','open','closed','completed','none'],true)?$phase:'closed';
}
function cms_phase_label(array $event): string {
 $phase=cms_event_phase($event);
 if(az_participation_mode($event)==='contribution')return match($phase){'open'=>'Contributions open','closed'=>'Contributions closed','completed'=>'Event completed',default=>'Programme preview'};
 if(az_participation_mode($event)==='performers')return ['interest'=>'Live performances','open'=>'Performer applications open','closed'=>'Performer applications closed','completed'=>'Event completed'][$phase];
 return ['interest'=>$event['status_label']?:'Programme preview','open'=>'Registration open','closed'=>'Registration closed','completed'=>'Event completed','none'=>'No registration required'][$phase];
}
function cms_flash(string $message,string $kind='success'): void {$_SESSION['cms_flash']=['message'=>$message,'kind'=>$kind];}
function cms_escape_lines(string $text): string {return nl2br(e($text),false);}
