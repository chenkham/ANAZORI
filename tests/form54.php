<?php
declare(strict_types=1);
if(getenv('ANAZORI_SQL_QA')!=='1')putenv('ANAZORI_DB_PATH=:memory:');
putenv('ANAZORI_TEST_MODE=1');
require __DIR__.'/../src/includes/commerce.php';
require __DIR__.'/../src/includes/cms-fields.php';
require __DIR__.'/../src/includes/event-setup-view.php';
$db=cms_db();$checks=0;
function form_check(bool $ok,string $message):void{global $checks;if(!$ok)throw new RuntimeException($message);$checks++;}
function form_denied(callable $call,string $message):void{try{$call();}catch(InvalidArgumentException|RuntimeException){form_check(true,$message);return;}throw new RuntimeException('Expected rejection: '.$message);}
$rows=[
 ['id'=>'issued-id','label'=>'Issued team ID','type'=>'text','required'=>1,'allowed_values'=>"0017\n0018"],
 ['id'=>'format','label'=>'Preferred format','type'=>'radio','required'=>1,'options'=>"Solo\nTeam\n0"],
 ['id'=>'days','label'=>'Available days','type'=>'multiselect','required'=>1,'options'=>"Monday\nTuesday\nWednesday"],
 ['id'=>'optional','label'=>'Optional choices','type'=>'multiselect','options'=>"0\n1"],
];
$json=az_validate_registration_fields($rows);$fields=['registration_form'=>$json,'interest_form'=>$json];$parsed=json_decode($json,true);
form_check($parsed[1]['options']===['Solo','Team','0'],'Zero remains a valid option');
form_check(!$parsed[3]['required'],'Optional checkbox questions stay optional');
$valid=['issued-id'=>'0017','format'=>'0','days'=>['Wednesday','Monday','Monday']];
$answer=az_registration_answers($fields,$valid);
form_check($answer['Issued team ID']==='0017','Issued team ID keeps its leading zeros');
form_check($answer['Preferred format']==='0','A single choice may be zero');
form_check($answer['Available days']==="Monday\nWednesday",'Multiple choices deduplicate in form order');
form_check($answer['Optional choices']==='','Optional multiple choices accept no selection');
form_check(az_registration_answers($fields,$valid,'interest')===$answer,'Both phases support the new choice types');
form_denied(fn()=>az_registration_answers($fields,array_replace($valid,['format'=>['Solo']])),'Single choice rejects arrays');
form_denied(fn()=>az_registration_answers($fields,array_replace($valid,['format'=>'Other'])),'Single choice rejects unlisted answers');
form_denied(fn()=>az_registration_answers($fields,array_replace($valid,['days'=>[]])),'Required checkboxes need a selection');
form_denied(fn()=>az_registration_answers($fields,array_replace($valid,['days'=>'Monday'])),'Multiple choices reject scalar strings');
form_denied(fn()=>az_registration_answers($fields,array_replace($valid,['days'=>[['Monday']]])),'Multiple choices reject nested arrays');
form_denied(fn()=>az_registration_answers($fields,array_replace($valid,['days'=>['Unlisted']])),'Multiple choices reject unknown options');
form_denied(fn()=>az_registration_answers($fields,array_replace($valid,['days'=>array_fill(0,51,'Monday')])),'Multiple choice payload count is bounded');
form_denied(fn()=>az_registration_answers($fields,array_replace($valid,['issued-id'=>'17'])),'Organiser ID lists remain private and strict');
form_denied(fn()=>az_validate_registration_fields([['label'=>'Only one','type'=>'radio','options'=>"A\nA"]]),'Choice questions require distinct options');
form_denied(fn()=>az_validate_registration_fields([['label'=>'Too many','type'=>'multiselect','options'=>implode("\n",range(1,51))]]),'Choice lists are bounded');
form_denied(fn()=>az_validate_registration_fields([['label'=>'Choice too long','type'=>'radio','options'=>str_repeat('x',121)."\nB"]]),'Choice labels are bounded');
form_denied(fn()=>az_validate_registration_fields(array_fill(0,101,['label'=>'x'])),'Forms are bounded to 100 items');
$approved=$fields;$only=json_decode($json,true);$only[2]['allowed_values']=['Monday'];$approved['registration_form']=json_encode($only);
form_denied(fn()=>az_registration_answers($approved,$valid),'Accepted values also validate individual checkbox choices');
form_check(!isset(az_public_registration_schema($fields)[0]['allowed_values']),'Private ID values excluded from public snapshots');
$rows[0]['label']='Your issued team code';$moved=[$rows[2],$rows[0],$rows[1],$rows[3]];$moved=json_decode(az_validate_registration_fields($moved),true);
form_check($moved[1]['id']==='issued-id'&&$moved[1]['label']==='Your issued team code','Rename and reorder retain field identities');
$duplicate=$rows[0];$duplicate['id']='';$duplicate['label']='Issued team ID (copy)';$copied=json_decode(az_validate_registration_fields([$rows[0],$duplicate]),true);
form_check($copied[0]['id']!==$copied[1]['id'],'Duplicate questions receive a new field identity');
$gameSchema=['registration_form'=>az_validate_registration_fields([['id'=>'mlbb-choice','label'=>'MLBB choice','type'=>'multiselect','required'=>1,'options'=>"Solo\nTeam",'game'=>'mlbb']],[['id'=>'mlbb']])];
form_check(az_registration_answers($gameSchema,[],'registration','bgmi')===[],'Hidden game questions do not become required');
$schema=cms_content_schema()['event']['fields'];
$render=function(string $slug)use($schema):string{$event=az_event($slug);ob_start();st_event_setup_fields($schema,$event['fields'],[],$slug,(int)$event['id']);return ob_get_clean();};
$treasure=$render('treasure-hunt');$joystick=$render('joystick');
form_check(!str_contains($treasure,'Add game')&&!str_contains($treasure,'Show for game')&&!str_contains($treasure,'Game (optional)'),'All game controls are absent outside Joystick');
form_check(str_contains($joystick,'Add game')&&str_contains($joystick,'name="ticket_categories81"')&&str_contains($joystick,'Add ticket category'),'Joystick retains games and configurable ticket categories');
form_check(str_contains($treasure,'Form setup')&&str_contains($treasure,'phase=registration')&&str_contains($treasure,'phase=interest'),'Both forms open from Form setup');
form_check(!str_contains($treasure,'data-question-duplicate')&&!str_contains($treasure,'data-form-builder'),'Question creation lives in the dedicated editor');
$previous=az_event('treasure-hunt')['fields'];$tampered=array_replace($previous,['registration_form'=>'[]','interest_form'=>'[]','registration_questions'=>'Injected','registration_intro'=>'Injected']);
$preserved=st_preserve_event_forms($tampered,$previous);
foreach(st_fixed_form_keys() as $key)form_check($preserved[$key]===($previous[$key]??cms_content_schema()['event']['fields'][$key][2]??''),'Event saves retain fixed '.$key);
form_check(!str_contains($treasure,'name="registration_intro"'),'Form presentation is edited in its dedicated workspace');
ob_start();az_registration_field($parsed[2]);$html=ob_get_clean();
form_check(str_contains($html,'name="answers[days][]"')&&str_contains($html,'data-required-choices'),'Public checkboxes use grouped answers and required validation');
ob_start();az_registration_field($parsed[1]);$html=ob_get_clean();
form_check(str_contains($html,'type="radio"')&&str_contains($html,'value="0"'),'Public single-choice radios support zero');
ob_start();az_registration_field(array_replace($parsed[1],['label'=>'<script>alert(1)</script>','options'=>['<b>Yes</b>','" onclick="bad']]));$html=ob_get_clean();
form_check(!str_contains($html,'<script>')&&!str_contains($html,'<b>')&&str_contains($html,'&quot;'),'Participant form output escapes labels and choices');
$formats=[
 ['id'=>'long','label'=>'Story','type'=>'textarea','required'=>1],['id'=>'drop','label'=>'Dropdown','type'=>'select','options'=>"A\nB"],
 ['id'=>'rating','label'=>'Rating','type'=>'rating','min'=>'1','max'=>'5'],['id'=>'date','label'=>'Date','type'=>'date'],['id'=>'time','label'=>'Time','type'=>'time'],
 ['id'=>'email','label'=>'Email','type'=>'email'],['id'=>'phone','label'=>'Phone','type'=>'tel'],['id'=>'number','label'=>'Number','type'=>'number','min'=>'1','max'=>'9'],
 ['id'=>'consent','label'=>'Consent','type'=>'checkbox','required'=>1],['id'=>'grid','label'=>'Grid','type'=>'checkgrid','required'=>1,'rows'=>"Day 1\nDay 2",'options'=>"Tech\nCulture"],
 ['id'=>'quiz','label'=>'Quiz','type'=>'radio','options'=>"A\nB",'points'=>'5','answer_key'=>'A'],
];
$formatFields=['registration_form'=>az_validate_registration_fields($formats)];
$formatAnswers=['long'=>'A participant story','drop'=>'B','rating'=>'5','date'=>'2026-10-10','time'=>'14:30','email'=>'person@example.invalid','phone'=>'+91 9876543210','number'=>'3.5','consent'=>'yes','grid'=>[['Tech'],['Culture']],'quiz'=>'A'];
$validated=az_registration_answers($formatFields,$formatAnswers);
form_check($validated['Number']==='3.5'&&$validated['Consent']==='Yes','Number ranges and consent answers validate');
form_check(az_form_score(json_decode($formatFields['registration_form'],true),$validated)===[5,5],'Quiz keys score answers');
form_check(!isset(az_public_registration_schema($formatFields)[10]['answer_key']),'Quiz keys stay private');
foreach(['date'=>'2026-02-30','time'=>'25:00','email'=>'invalid','number'=>'10','consent'=>'no','grid'=>[[['Tech']],['Culture']]] as $key=>$invalid)
 form_denied(fn()=>az_registration_answers($formatFields,array_replace($formatAnswers,[$key=>$invalid])),'Malformed '.$key.' answer is rejected');
form_denied(fn()=>az_form_lines([['nested']]),'Malformed choice lists are rejected');
echo "PASS $checks form setup, question formats, quiz keys, choice validation, stable IDs and Joystick scope checks.\n";
