<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli')exit;
putenv('ANAZORI_PRIVATE_CONFIG=/nonexistent');putenv('ANAZORI_DB_DRIVER=sqlite');putenv('ANAZORI_DB_PATH=:memory:');putenv('ANAZORI_APP_KEY='.base64_encode(random_bytes(32)));putenv('ANAZORI_TEST_MODE=1');putenv('ANAZORI_MAIL_NOTIFICATIONS=1');putenv('ANAZORI_SITE_URL=https://anazori.ccsdu.in');
foreach(['DAILY_LIMIT','PER_MINUTE','SENDER_DAILY_LIMIT','SENDER_PER_MINUTE'] as $key)putenv('ANAZORI_PHP_MAIL_'.$key.'=1000');
$outbox=sys_get_temp_dir().'/anazori-lifecycle107-'.bin2hex(random_bytes(8));mkdir($outbox,0700);putenv('ANAZORI_TEST_OUTBOX='.$outbox);
require __DIR__.'/../src/includes/commerce.php';
$db=cms_db();$checks=0;$now=time();$db->exec("UPDATE users SET must_change_password=0 WHERE role='SUPERADMIN'");$master=$db->query("SELECT * FROM users WHERE role='SUPERADMIN'")->fetch();
function check107(bool $yes,string $label): void {global $checks;if(!$yes)throw new RuntimeException($label);$checks++;}
function person107(): array {global $db;$db->prepare('INSERT INTO az_participants(email,name,email_verified,profile_completed,created_at) VALUES(?,?,1,1,?)')->execute(['mail-'.bin2hex(random_bytes(5)).'@example.invalid','Mail <Participant>',gmdate('c')]);return $db->query('SELECT * FROM az_participants ORDER BY id DESC LIMIT 1')->fetch();}
function event107(array $changes): array {global $db;$event=az_event('tulika');$fields=array_replace($event['fields'],$changes);$db->prepare('UPDATE cms_content SET data=? WHERE id=?')->execute([json_encode($fields),$event['id']]);return az_event('tulika');}
function order107(): array {$person=person107();az_participant_login($person);return az_create_form_order($person,'tulika','entry',1,['details'=>'Private answer: never email this'],[]);}
function messages107(): array {global $outbox;return array_map(fn($path)=>json_decode(file_get_contents($path),true),glob($outbox.'/*.json'));}
function clear107(): void {global $db;$db->exec('DELETE FROM az_mail_jobs89');}
function lastJob107(): array {global $db;return $db->query('SELECT * FROM az_mail_jobs89 ORDER BY id DESC LIMIT 1')->fetch();}
try{
 $event=event107(['registration_mode'=>'open','registration_opens'=>'','registration_closes'=>'','ends_at'=>'','registration_url'=>'','game_categories'=>'[]','form_workflow'=>'1','reminder_window'=>'24h','starts_at'=>gmdate('c',$now+72*3600),'venue'=>'Main hall','ticket_types'=>az_validate_prices([['id'=>'entry','label'=>'Festival entry','price'=>'0','active'=>1]]),'registration_form'=>az_validate_registration_fields([['id'=>'details','label'=>'Details','type'=>'text','required'=>1]]),'registration_settings'=>json_encode(['accepting'=>true,'allow_edit'=>true])]);
 $order=order107();$job=lastJob107();$data=json_decode(az_decrypt($job['payload']),true);
 check107($job['kind']==='registration_received','A saved registration queues a submission acknowledgement.');
 check107(!str_contains($job['payload'],$data['email'])&&!isset($data['answers'])&&!str_contains(json_encode($data),'Private answer'),'Receipt payload is encrypted and excludes private answers.');
 check107(az_run_mail_worker89(10)['sent']===1,'Submission acknowledgement is deliverable before approval.');
 $messages=messages107();$message=end($messages);check107(str_contains($message['subject'],'registration is received')&&str_contains($message['body'],'not an approval or entry ticket'),'Submission template clearly describes pending review.');
 $person=$db->query('SELECT * FROM az_participants WHERE id='.(int)$order['participant_id'])->fetch();
 az_create_form_order($person,'tulika','entry',1,['details'=>'Edited private answer'],[],'',(int)$order['id'],(int)az_form_response((int)$order['id'])['revision']);
 check107((int)$db->query("SELECT COUNT(*) FROM az_mail_jobs89 WHERE kind='registration_received'")->fetchColumn()===1&&az_run_mail_worker89(10)['sent']===0,'Editing and repeated queue calls cannot resend the acknowledgement.');
 $db->beginTransaction();az_queue_mail89('rollback107','registration_received',['email'=>$person['email']],(int)$order['id'],(int)$person['id']);$db->rollBack();check107((int)$db->query('SELECT COUNT(*) FROM az_mail_jobs89')->fetchColumn()===1,'A rolled-back transaction cannot leave an email job.');
 az_review_form_order($master,(int)$order['id'],'approve',['revision'=>az_form_response((int)$order['id'])['revision']]);$order=az_order((int)$order['id']);az_issue_tickets($order);
 check107((int)$db->query("SELECT COUNT(*) FROM az_mail_jobs89 WHERE kind='ticket_confirmed'")->fetchColumn()===1,'Approval queues one ticket email even if issuance is repeated.');
 check107(az_run_mail_worker89(10)['sent']===1,'The approved-ticket email is sent.');
 $ticket=$db->query('SELECT * FROM az_tickets WHERE order_id='.(int)$order['id'])->fetch();
 foreach(messages107() as $message){check107(in_array($message['from'],az_mail_senders95('notice'),true),'Event mail uses the notice sender pair.');check107(!str_contains($message['body'],$ticket['token']),'Private scanner token never appears in email.');}
 $quick=order107();az_review_form_order($master,(int)$quick['id'],'approve',['revision'=>az_form_response((int)$quick['id'])['revision']]);$result=az_run_mail_worker89(10);
 check107($result['skipped']===1&&$result['sent']===1,'An approval overtaking a queued receipt sends only the current approval.');
 $db->prepare("UPDATE az_tickets SET status='BLOCKED' WHERE order_id=?")->execute([$quick['id']]);
 $declined=order107();az_review_form_order($master,(int)$declined['id'],'decline',['revision'=>az_form_response((int)$declined['id'])['revision'],'note'=>'Not eligible']);
 check107(az_run_mail_worker89(10)['skipped']===1&&(int)$db->query("SELECT COUNT(*) FROM az_mail_jobs89 WHERE kind='ticket_rejected'")->fetchColumn()===0,'The current three-email policy excludes rejections and obsolete receipts.');
 clear107();$start=$now+24*3600+120;event107(['starts_at'=>gmdate('c',$start),'reminder_window'=>'24h']);
 check107(az_schedule_reminders89($now+119)===0,'24-hour reminder is not queued early.');check107(az_schedule_reminders89($now+120)===1,'24-hour reminder queues at its boundary.');check107(az_schedule_reminders89($now+120)===0,'Repeated scheduling is idempotent.');
 clear107();$start=$now+12*3600+120;event107(['starts_at'=>gmdate('c',$start),'reminder_window'=>'12h']);
 check107(az_schedule_reminders89($now+119)===0,'12-hour reminder is not queued early.');check107(az_schedule_reminders89($now+120)===1,'12-hour reminder queues at its boundary.');
 clear107();$start=$now+18*3600;event107(['starts_at'=>gmdate('c',$start),'reminder_window'=>'24h']);az_schedule_reminders89(time());event107(['reminder_window'=>'12h']);
 $result=az_run_mail_worker89(10);$job=lastJob107();check107($result['sent']===0&&$result['retried']===1&&$job['status']==='pending','Switching to a 12-hour reminder defers an already queued 24-hour reminder.');
 check107((int)$job['available_at']===$start-12*3600&&(int)$job['attempts']===0,'Deferral preserves retry budget and correct send time.');
 event107(['reminder_window'=>'24h','venue'=>'Updated venue']);check107(az_run_mail_worker89(10)['sent']===1,'Switching back to 24 hours advances a deferred reminder.');check107(az_schedule_reminders89(time())===0,'Changing lead time does not send a second reminder.');
 $reminders=array_values(array_filter(messages107(),fn($message)=>str_contains($message['subject'],'event is coming up')));check107(str_contains(end($reminders)['body'],'Updated venue'),'Reminder uses the latest venue.');
 clear107();event107(['starts_at'=>gmdate('c',$now+20*3600)]);az_schedule_reminders89(time());event107(['starts_at'=>gmdate('c',$now+22*3600)]);$result=az_run_mail_worker89(10);check107($result['skipped']===1&&$result['sent']===1,'A rescheduled start invalidates the old reminder.');
 clear107();event107(['starts_at'=>gmdate('c',$now+21*3600)]);az_schedule_reminders89(time());$db->prepare("UPDATE cms_content SET status='DRAFT' WHERE id=?")->execute([$event['id']]);check107(az_run_mail_worker89(10)['sent']===0,'Unpublished events do not send reminders.');$db->prepare("UPDATE cms_content SET status='PUBLISHED' WHERE id=?")->execute([$event['id']]);
 clear107();$db->prepare("UPDATE az_tickets SET status='USED' WHERE order_id=?")->execute([$order['id']]);check107(az_schedule_reminders89(time())===0,'Used and blocked tickets do not receive reminders.');$db->prepare("UPDATE az_tickets SET status='VALID' WHERE order_id=?")->execute([$order['id']]);
 event107(['starts_at'=>gmdate('c',$now-60)]);check107(az_schedule_reminders89(time())===0,'No reminder after the event starts.');
 foreach(['','tomorrow','2026-02-31T09:00'] as $date)check107(az_event_start101(['starts_at'=>$date])===null,'Invalid or relative event dates are rejected.');
 check107(az_event_start101(['starts_at'=>'2026-11-02T09:00'])===(new DateTimeImmutable('2026-11-02T09:00:00+05:30'))->getTimestamp(),'Unqualified event times use India time.');
 clear107();foreach(['ticket_rejected','interest_received','contribution_received','welcome','refund'] as $kind)az_queue_mail89('excluded:'.$kind,$kind,['email'=>'scope@example.invalid']);check107(!$db->query('SELECT id FROM az_mail_jobs89')->fetch(),'Only submission, approval and reminder categories can queue.');
 $db->prepare("INSERT INTO az_mail_jobs89(dedupe_key,kind,payload,available_at,created_at) VALUES(?,'interest_received','old payload',0,?)")->execute([hash('sha256','legacy107'),time()]);check107(az_run_mail_worker89(10)['skipped']===1,'Unsupported old jobs are skipped.');
 $preview=az_mail_template('registration_received',['name'=>'<script>visitor</script>','event'=>'Event <unsafe>']);check107(!str_contains($preview['html'],'<script>')&&str_contains($preview['html'],'email-wordmark101.png'),'Receipt escapes HTML and retains the Anazori email theme.');
 $bad=false;try{az_mail_template('ticket_confirmed',['path'=>'https://evil.example']);}catch(InvalidArgumentException){$bad=true;}check107($bad,'Email actions reject external destinations.');
 clear107();putenv('ANAZORI_TEST_MAIL_FAIL_SENDERS=noreply3@ccsdu.in');az_notify_order89($order,'ticket_confirmed','fallback107',['ticket'=>$ticket['ticket_id']]);check107(az_run_mail_worker89(10)['sent']===1,'Notice transport failure retries with its paired sender.');
 $approved=array_values(array_filter(messages107(),fn($message)=>str_contains($message['subject'],'ticket is ready')&&$message['from']==='noreply4@ccsdu.in'));check107(count($approved)===1,'Approval fallback stays within noreply3/noreply4.');
 putenv('ANAZORI_TEST_MAIL_FAIL_SENDERS=noreply3@ccsdu.in,noreply4@ccsdu.in');$db->exec('DELETE FROM az_mail_sender95');az_notify_order89($order,'ticket_confirmed','retry107',['ticket'=>$ticket['ticket_id']]);$result=az_run_mail_worker89(10);check107($result['retried']===1&&lastJob107()['status']==='pending','Failure on both notice senders leaves a retriable job.');
 putenv('ANAZORI_TEST_MAIL_FAIL_SENDERS');$db->exec('DELETE FROM az_mail_sender95');$db->exec('UPDATE az_mail_jobs89 SET available_at=0');check107(az_run_mail_worker89(10)['sent']===1,'A subsequent worker run recovers failed delivery without duplicating the ticket.');
 echo "PASS $checks submission, approval, reminder, privacy, failover and retry checks.\n";
}finally{foreach(glob($outbox.'/*.json')?:[] as $file)unlink($file);rmdir($outbox);}
