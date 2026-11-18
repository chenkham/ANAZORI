<?php
declare(strict_types=1);
require_once __DIR__.'/../config/db.php';
require_once __DIR__.'/../includes/festival.php';
require_once __DIR__.'/../includes/commerce.php';
header('Content-Type: application/json; charset=utf-8');
set_security_headers();
function interest_reply(array $data,int $status=200): never {http_response_code($status);echo json_encode($data,JSON_UNESCAPED_UNICODE);exit;}
if(($_SERVER['REQUEST_METHOD']??'')!=='POST') {header('Allow: POST');interest_reply(['success'=>false,'error'=>'Use POST to register interest.'],405);}
if((int)($_SERVER['CONTENT_LENGTH']??0)>65*1024*1024) interest_reply(['success'=>false,'error'=>'The form is too large. Use at most 60 MB of files.'],413);
$token=$_POST['csrf_token']??'';
if(!is_string($token)||!csrf_verify($token)) interest_reply(['success'=>false,'error'=>'Your session expired. Refresh the page and try again.'],403);
if(!rate_limit_check('interest_2026',8,300)) interest_reply(['success'=>false,'error'=>'Please wait a few minutes before trying again.'],429);
function interest_text(string $key,int $min,int $max): string {
 $value=$_POST[$key]??'';if(!is_string($value))interest_reply(['success'=>false,'error'=>'Please check the '.$key.' field.'],422);
 $value=trim($value);
 if(mb_strlen($value)<$min||mb_strlen($value)>$max||preg_match('/[<>\x00-\x1F]/u',$value))interest_reply(['success'=>false,'error'=>'Please check the '.$key.' field.'],422);
 return $value;
}
$slug=interest_text('event',1,60);
if(!isset($festival['events'][$slug]))interest_reply(['success'=>false,'error'=>'Please select an available experience.'],422);
$event=$festival['events'][$slug];$phase=cms_event_phase($event);$purpose=$_POST['purpose']??'interest';
if(!is_string($purpose)||!in_array($purpose,['interest','contribution'],true))interest_reply(['success'=>false,'error'=>'Use the registration form linked on the event page.'],422);
// Public forms accept contact details directly and never require a participant account.
$contribution=$purpose==='contribution';$type=$contribution?'CONTRIBUTION':'INTEREST';$schemaPhase=$contribution?'registration':'interest';
if((az_participation_mode($event)==='contribution')!==$contribution)interest_reply(['success'=>false,'error'=>'Choose the form linked on the event page.'],422);
$gameId=$_POST['game']??'';if(!is_string($gameId))interest_reply(['success'=>false,'error'=>'Choose an available game.'],422);
try{$game=az_selected_game($event,$gameId);$event=az_game_fields81($event,$gameId,$schemaPhase);}catch(Throwable $error){interest_reply(['success'=>false,'error'=>$error->getMessage()],422);}
$settings=az_form_settings($event,$schemaPhase);if(empty($settings['accepting']))interest_reply(['success'=>false,'error'=>'This form is no longer accepting responses.'],422);
if(($contribution&&$phase!=='open')||(!$contribution&&($phase!=='interest'||$event['interest_open']!=='1')))interest_reply(['success'=>false,'error'=>'This submission phase is closed. Refresh the event page for the latest status.'],422);
$name=interest_text('name',2,100);$email=strtolower(interest_text('email',3,254));
if(!filter_var($email,FILTER_VALIDATE_EMAIL))interest_reply(['success'=>false,'error'=>'Please enter a valid email address.'],422);
if(($_POST['consent']??'')!=='yes')interest_reply(['success'=>false,'error'=>'Please agree to the form notice.'],422);
$posted=$_POST['answers']??[];if(!is_array($posted))interest_reply(['success'=>false,'error'=>'Check your form answers.'],422);
// Accept the old default field names while existing cached pages finish their submissions.
foreach(['college','phone'] as $key)if(!isset($posted[$key])&&isset($_POST[$key]))$posted[$key]=$_POST[$key];
try{
 $answers=az_registration_answers($event,$posted,$schemaPhase,$gameId);
 az_limit('public-form.ip',$_SERVER['REMOTE_ADDR']??'unknown',40,900);az_limit('public-form.email',$email,10,900);
 $groups=az_collect_form_uploads($event,$posted,$_FILES['uploads']??[],$schemaPhase,$gameId);
}catch(InvalidArgumentException|RuntimeException $error){interest_reply(['success'=>false,'error'=>$error->getMessage()],422);}
$college=is_string($posted['college']??null)?trim($posted['college']):'';$phone=is_string($posted['phone']??null)?trim($posted['phone']):'';
 $written=[];
try {
 $db=Database::getConnection();
 $find=$db->prepare('SELECT id FROM events WHERE slug=? LIMIT 1');$find->execute([$slug]);$eventId=$find->fetchColumn();
 if(!$eventId)interest_reply(['success'=>false,'error'=>'This experience is not available yet. Please contact the organisers.'],503);
 // Store 2026 interest separately in form_data, retaining the existing organiser dashboard and all historical records.
 $db->beginTransaction();
 $db->exec("UPDATE cms_settings SET value=value WHERE setting_key='schema_version'");
 $previous=$db->prepare('SELECT id,form_data FROM submissions WHERE event_id=? AND email=? ORDER BY id DESC');$previous->execute([$eventId,$email]);
 $edition=(int)setting('year');if(!empty($settings['one_response']))foreach($previous as $row){$data=json_decode($row['form_data']??'{}',true);if(($data['edition']??null)===$edition&&($data['type']??'')===$type&&($slug!=='joystick'||($data['game_id']??'')===$gameId)){$db->commit();interest_reply(['success'=>true,'reference'=>$data['reference'],'message'=>'Your details are already saved.']);}}
 $reference='AZ'.substr((string)$edition,-2).'-'.strtoupper(bin2hex(random_bytes(5)));
 $data=['edition'=>$edition,'version'=>setting('version'),'type'=>$type,'college'=>$college,'reference'=>$reference,'email_verified'=>false,'game_id'=>$game['id']??'','game'=>$game['label']??'','form_schema'=>az_public_registration_schema($event,$schemaPhase),'consent'=>'Agreed to storage and event contact','notice'=>$contribution?'Contribution or performance proposal':'Interest response only'];if($answers)$data['answers']=$answers;
 $insert=$db->prepare("INSERT INTO submissions(event_id,name,phone,email,form_data,payment_proof,status) VALUES(?,?,?,?,?,NULL,?)");
 $insert->execute([$eventId,$name,$phone,$email,json_encode($data,JSON_UNESCAPED_UNICODE),$contribution?'RECEIVED':'INTEREST']);
 $submissionId=(int)$db->lastInsertId();$cmsEvent=az_event($slug);
 $answers=array_replace($answers,az_save_form_uploads($db,$groups,(int)$cmsEvent['id'],null,null,$submissionId,$written));$data['answers']=$answers;
 if(!empty($settings['quiz']))[$data['score'],$data['max_score']]=az_form_score(az_registration_fields($event,$purpose),$answers);
 $db->prepare('UPDATE submissions SET form_data=? WHERE id=?')->execute([json_encode($data,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR),$submissionId]);
 $db->commit();interest_reply(['success'=>true,'reference'=>$reference,'message'=>$contribution?'Thank you. Your contribution has been sent to the event team.':'Thank you for sharing your interest.'],201);
}catch(Throwable $error){if(isset($db)&&$db->inTransaction())$db->rollBack();foreach($written as $path)@unlink($path);error_log('Anazori interest storage failed.');interest_reply(['success'=>false,'error'=>'We could not save your interest. Please try again later.'],503);}
