<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli')exit('CLI only');
putenv('ANAZORI_DB_PATH=:memory:');putenv('ANAZORI_TEST_MODE=1');
require __DIR__.'/../src/includes/commerce.php';
$db=cms_db();$checks=0;
function payment_check85(bool $condition,string $label): void {global $checks;if(!$condition)throw new RuntimeException($label);$checks++;}
function payment_denied85(callable $call,string $label): void {try{$call();}catch(RuntimeException|InvalidArgumentException){payment_check85(true,$label);return;}throw new RuntimeException('Expected rejection: '.$label);}
$event=az_event('paper-presentation');$fields=$event['fields'];
$fields['registration_mode']='open';$fields['registration_opens']='';$fields['registration_closes']='';$fields['form_workflow']='1';
$fields['ticket_types']=az_validate_prices([
 ['id'=>'single','label'=>'Single','price'=>'100','people'=>1,'active'=>1],
 ['id'=>'duo','label'=>'Duo','price'=>'250','people'=>2,'active'=>1],
 ['id'=>'free','label'=>'Free category','price'=>'0','active'=>1],
]);
$rows=[
 ['id'=>'college','label'=>'College','type'=>'text','required'=>1],
 ['id'=>'qr-single','label'=>'Single QR','type'=>'image','media'=>'/assets/logo.png','payment_ticket'=>'single','payment_upi'=>'single@bank','help'=>'Pay the Single category amount.'],
 ['id'=>'qr-duo','label'=>'Duo QR','type'=>'image','media'=>'/assets/logo.png','payment_ticket'=>'duo','payment_upi'=>'duo@bank','help'=>'Pay the Duo category amount.'],
 ['id'=>'reference','label'=>'Transaction reference','type'=>'text','purpose'=>'payment','required'=>1],
 ['id'=>'receipt','label'=>'Payment screenshot','type'=>'file','purpose'=>'payment','file_types'=>'images'],
];
$fields['registration_form']=az_validate_registration_fields($rows);
az_validate_ticket_qrs85($fields);payment_check85(count(az_ticket_qrs85($fields))===2,'Each QR is linked to one existing ticket.');
foreach(['unknown','free'] as $invalid){$bad=$rows;$bad[1]['payment_ticket']=$invalid;payment_denied85(fn()=>az_validate_ticket_qrs85(array_replace($fields,['registration_form'=>az_validate_registration_fields($bad)])),'Unknown/free tickets cannot request payment.');}
$bad=$rows;$bad[2]['payment_ticket']='single';payment_denied85(fn()=>az_validate_ticket_qrs85(array_replace($fields,['registration_form'=>az_validate_registration_fields($bad)])),'Duplicate QR links rejected.');
$bad=$rows;unset($bad[2]);payment_denied85(fn()=>az_validate_ticket_qrs85(array_replace($fields,['registration_form'=>az_validate_registration_fields($bad)])),'All paid ticket categories need a QR when linking is used.');
$bad=$rows;$bad[2]['payment_ticket']='';payment_denied85(fn()=>az_validate_ticket_qrs85(array_replace($fields,['registration_form'=>az_validate_registration_fields($bad)])),'A general payment QR cannot override ticket-specific QRs.');
payment_denied85(fn()=>az_validate_registration_fields([array_replace($rows[0],['payment_ticket'=>'single'])]),'Answer fields cannot claim a QR link.');
payment_denied85(fn()=>az_validate_ticket_qrs85(array_replace($fields,['interest_form'=>$fields['registration_form']]),'interest'),'Interest forms do not collect ticket payments.');
$bad=$rows;$bad[1]['condition_field']='college';$bad[1]['condition_value']='One college';payment_denied85(fn()=>az_validate_ticket_qrs85(array_replace($fields,['registration_form'=>az_validate_registration_fields($bad)])),'A QR cannot be hidden by an earlier-answer condition.');
$bad=$rows;array_splice($bad,1,0,[['id'=>'payment-section','label'=>'Payment','type'=>'section','condition_field'=>'college','condition_value'=>'One college']]);payment_denied85(fn()=>az_validate_ticket_qrs85(array_replace($fields,['registration_form'=>az_validate_registration_fields($bad)])),'The ticket selector and linked QRs require an unconditional section.');
$gameFields=array_replace($fields,['_form_game'=>'mlbb','ticket_types'=>az_validate_prices([
 ['id'=>'single','label'=>'MLBB','price'=>'100','game'=>'mlbb','active'=>1],
 ['id'=>'duo','label'=>'BGMI','price'=>'250','game'=>'bgmi','active'=>1],
])]);payment_denied85(fn()=>az_validate_ticket_qrs85($gameFields),'A game form cannot link the payment QR of another game.');
$single=array_replace($fields,['_ticket_id'=>'single','_ticket_price'=>10000]);
$visible=array_column(az_visible_form_fields($single,['college'=>'Test college']),'id');payment_check85(in_array('qr-single',$visible,true)&&!in_array('qr-duo',$visible,true),'Only the selected ticket QR is active on the server.');
$free=array_replace($fields,['_ticket_id'=>'free','_ticket_price'=>0]);
payment_check85(az_registration_answers($free,['college'=>'Test college'])===['College'=>'Test college'],'Free tickets do not require payment answers.');
ob_start();az_registration_form($fields,'registration',[],[],fn()=>az_checkout_ticket_picker85(az_ticket_options81($fields),'') );$html=ob_get_clean();
payment_check85(strpos($html,'registration-college')<strpos($html,'data-ticket-picker')&&strpos($html,'data-ticket-picker')<strpos($html,'data-field-id="qr-single"'),'Ticket selection follows details and sits directly above the QRs.');
payment_check85(substr_count($html,'data-ticket-picker')===1,'Only one ticket selector is rendered.');
$db->prepare('UPDATE cms_content SET data=? WHERE id=?')->execute([json_encode($fields),$event['id']]);
$db->prepare('INSERT INTO az_participants(email,name,email_verified,profile_completed,created_at) VALUES(?,?,1,1,?)')->execute(['ticket-payment@example.invalid','Test participant',gmdate('c')]);$user=$db->query('SELECT * FROM az_participants ORDER BY id DESC LIMIT 1')->fetch();
az_participant_login($user);
az_save_checkout_draft($user,$event,['answers'=>['college'=>'Saved college'],'type'=>'duo','draft_revision'=>0],[]);
$draft=az_checkout_draft((int)$user['id'],(int)$event['id']);payment_check85($draft['type_id']==='duo'&&json_decode($draft['answers_json'],true)['college']==='Saved college','Ticket selection and form answers survive leaving to pay.');
$order=az_create_form_order($user,$event['slug'],'duo',1,['college'=>'Test college','reference'=>'TEST-REFERENCE','amount'=>'1'],[]);
$snapshot=json_decode($order['snapshot'],true);
payment_check85((int)$order['amount']===25000&&$snapshot['ticket_payment']['payment_upi']==='duo@bank','The server fixes the amount and snapshots only the chosen payment setup.');
payment_check85((int)$db->query('SELECT COUNT(*) FROM az_tickets')->fetchColumn()===0,'Payment evidence still requires coordinator approval before a ticket is issued.');
$changed=$fields;$changed['ticket_types']=str_replace('25000','30000',$changed['ticket_types']);$changed['registration_form']=str_replace('duo@bank','changed@bank',$changed['registration_form']);$db->prepare('UPDATE cms_content SET data=? WHERE id=?')->execute([json_encode($changed),$event['id']]);
$response=az_form_response((int)$order['id']);
$edited=az_create_form_order($user,$event['slug'],'single',1,['college'=>'Edited college','reference'=>'TEST-REFERENCE'],[],'',(int)$order['id'],(int)$response['revision']);
payment_check85((int)$edited['amount']===25000&&$edited['ticket_type']==='duo'&&json_decode($edited['snapshot'],true)['ticket_payment']['payment_upi']==='duo@bank','Editing retains the original category, fee and payment account.');
$db->exec("UPDATE users SET must_change_password=0 WHERE role='SUPERADMIN'");$master=$db->query("SELECT * FROM users WHERE role='SUPERADMIN'")->fetch();$response=az_form_response((int)$order['id']);
az_review_form_order($master,(int)$order['id'],'approve',['revision'=>$response['revision'],'bank_confirmed'=>'yes','received_amount'=>'250','reference'=>'VERIFIED-REFERENCE-85','note'=>'Isolated test verification']);
$method=json_decode(az_manual_payment((int)$order['id'])['method_snapshot'],true);payment_check85($method['upi']==='duo@bank'&&(int)$db->query('SELECT COUNT(*) FROM az_tickets')->fetchColumn()===1,'Coordinator verification uses the original linked account and issues one ticket.');
echo "PASS $checks ticket-linked QR, fixed price, saved progress and approval checks.\n";
