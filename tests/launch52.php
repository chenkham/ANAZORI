<?php
declare(strict_types=1);
if(getenv('ANAZORI_SQL_QA')!=='1')putenv('ANAZORI_DB_PATH=:memory:');
putenv('ANAZORI_TEST_MODE=1');
require __DIR__.'/../src/includes/commerce.php';require __DIR__.'/../src/includes/google-auth.php';require __DIR__.'/../src/includes/studio-workspace.php';
$db=cms_db();$checks=0;
function launch_check(bool $yes,string $message):void{global $checks;if(!$yes)throw new RuntimeException($message);$checks++;}
function launch_denied(callable $call,string $message):void{try{$call();}catch(InvalidArgumentException|RuntimeException){launch_check(true,$message);return;}throw new RuntimeException('Expected rejection: '.$message);}
putenv('ANAZORI_SITE_URL=https://anazori.ccsdu.in');
$_SERVER['HTTP_HOST']='localhost:8000';launch_check(az_origin()==='http://localhost:8000','Local Google origin uses port 8000');
$_SERVER['HTTP_HOST']='anazori.ccsdu.in';launch_check(az_origin()==='https://anazori.ccsdu.in','Deployed Google origin uses the HTTPS domain');unset($_SERVER['HTTP_HOST']);
$games=[['id'=>'mlbb','label'=>'MLBB','active'=>true],['id'=>'bgmi','label'=>'BGMI','active'=>true]];
$form=az_validate_registration_fields([
 ['id'=>'team','label'=>'Team name','type'=>'text','required'=>1],
 ['id'=>'issued-id','label'=>'Issued ID','type'=>'text','required'=>1,'allowed_values'=>"0017\n0018"],
 ['id'=>'mlbb-id','label'=>'MLBB player ID','type'=>'text','required'=>1,'game'=>'mlbb'],
 ['id'=>'bgmi-id','label'=>'BGMI player ID','type'=>'text','required'=>1,'game'=>'bgmi'],
],$games);
$fields=['registration_form'=>$form,'interest_form'=>az_validate_registration_fields([['id'=>'format','label'=>'Preferred format','type'=>'select','required'=>1,'options'=>"Solo\nTeam"]])];
$answers=az_registration_answers($fields,['team'=>'Real team','issued-id'=>'0017','mlbb-id'=>'9001'],'registration','mlbb');
launch_check($answers['Issued ID']==='0017'&&!isset($answers['BGMI player ID']),'Leading zeros retained and other game fields excluded');
launch_denied(fn()=>az_registration_answers($fields,['team'=>'Team','issued-id'=>'17','mlbb-id'=>'9001'],'registration','mlbb'),'Unissued ID rejected');
launch_denied(fn()=>az_registration_answers($fields,['team'=>'Team','issued-id'=>'0017'],'registration','mlbb'),'Selected game required field enforced');
launch_check(az_registration_answers($fields,['format'=>'Team'],'interest')['Preferred format']==='Team','Interest uses its independent form');
launch_denied(fn()=>az_registration_answers($fields,['format'=>'Invalid'],'interest'),'Forged interest choice rejected');
launch_check(!isset(az_public_registration_schema($fields)[1]['allowed_values']),'Accepted ID list excluded from snapshots');
launch_denied(fn()=>az_validate_registration_fields([['id'=>'field','label'=>'Invalid game','type'=>'text','game'=>'missing']],$games),'Unknown game cannot be attached to a question');
$treasure=az_event('treasure-hunt')['fields'];
launch_check(in_array('issued-team-id',array_column(az_registration_fields($treasure),'id'),true),'Treasure Hunt registration has issued team ID');
launch_check(in_array('team-name',array_column(az_registration_fields($treasure,'interest'),'id'),true),'Treasure Hunt interest has team name');
launch_check(in_array('bgmi',array_column(az_event_games(az_event('joystick')['fields'],false),'id'),true),'Confirmed BGMI game available');
$newGoogle=az_google_participant($db,az_google_identity(['sub'=>'unknown-signin','email'=>'unknown-signin@example.invalid','email_verified'=>true]));
launch_check((int)$newGoogle['email_verified']===1&&!(int)$newGoogle['profile_completed'],'Unknown Google email creates an account requiring a full name');
launch_check(az_participant_destination($newGoogle,'/dashboard.php')==='/profile.php'&&$_SESSION['profile_next']==='/dashboard.php','New Google account completes its name before the dashboard');
$db->prepare('DELETE FROM az_participants WHERE id=?')->execute([$newGoogle['id']]);
$u=az_google_participant($db,az_google_identity(['sub'=>'launch52-local-fixture','email'=>'launch52@example.invalid','name'=>'Isolated test account','email_verified'=>true]));
az_participant_login($u,'google');az_auth_event('email_verified','email_otp',$u);
$history=$db->query('SELECT event,method,success FROM az_auth_events ORDER BY id DESC LIMIT 3')->fetchAll();
launch_check(array_column($history,'method')===['email_otp','google','google'],'Google signup/login and email verification recorded separately');
launch_check($u['name']===''&&!(int)$u['profile_completed'],'Google names are not imported into the participant profile');
launch_check(az_participant_destination($u,'/checkout.php?event=joystick')==='/profile.php'&&$_SESSION['profile_next']==='/checkout.php?event=joystick','Google onboarding preserves the intended event');
$updated=az_update_participant_profile($u,['name'=>'Chosen full name','phone'=>'+91 98765 43210','email'=>'forged@example.invalid','role'=>'SUPERADMIN']);
launch_check($updated['name']==='Chosen full name'&&$updated['phone']==='+91 98765 43210'&&(int)$updated['profile_completed']===1&&$updated['email']===$u['email'],'Only own name and phone can change');
launch_check(az_participant_destination($updated,'/checkout.php?event=joystick')==='/checkout.php?event=joystick','Completed profile continues to its event');
launch_denied(fn()=>az_update_participant_profile($updated,['name'=>'A','phone'=>'']),'Incomplete full name rejected');
launch_denied(fn()=>az_update_participant_profile($updated,['name'=>'Chosen full name','phone'=>'-------']),'Phone requires actual digits');
$relogin=az_google_participant($db,az_google_identity(['sub'=>'launch52-local-fixture','email'=>'launch52@example.invalid','name'=>'Changed Google name','email_verified'=>true]));
launch_check($relogin['name']==='Chosen full name'&&$relogin['phone']==='+91 98765 43210','Later Google sign-in preserves manually entered profile');
launch_check(az_participant_destination($relogin,'/dashboard.php')==='/dashboard.php','An existing completed Google account opens the dashboard');
az_participant_login($relogin,'google');
launch_denied(fn()=>az_google_participant($db,az_google_identity(['sub'=>'launch52-local-fixture','email'=>'changed-email@example.invalid','email_verified'=>true])),'Google subject alone cannot bypass the registered email');
launch_denied(fn()=>az_participant_login(array_replace($relogin,['id'=>999999])),'An absent database account cannot start a session');
$db->exec("UPDATE users SET must_change_password=0 WHERE role='SUPERADMIN'");$master=$db->query("SELECT * FROM users WHERE role='SUPERADMIN'")->fetch();
launch_check(count(st_operation_rows($master,'participants',null,'live'))===1,'Global participant register includes accounts without event orders');
launch_check(cms_can($master,'logins'),'Master can inspect sign-in history');
launch_check(isset(cms_content_schema()['collaboration']),'Collaboration publishing has its own module');
launch_check($db->query('SELECT COUNT(*) FROM cms_content WHERE type=\'collaboration\'')->fetchColumn()==0,'No invented collaborations are seeded');
$db->exec("INSERT INTO users(username,password_hash,role,active,must_change_password,permissions) VALUES('scoped-test','unused','COORDINATOR',1,0,'[\"participants.view\"]')");$scoped=$db->query("SELECT * FROM users WHERE username='scoped-test'")->fetch();
launch_check(!cms_can($scoped,'logins'),'Event coordinators cannot read global sign-in history');
echo "PASS $checks launch form, login history and publishing checks.\n";
