<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli')exit('CLI only');
putenv('ANAZORI_DB_PATH=:memory:');putenv('ANAZORI_TEST_MODE=1');
require __DIR__.'/../src/includes/commerce.php';
$db=cms_db();$checks=0;
function expect(bool $condition,string $message): void {global $checks;if(!$condition)throw new RuntimeException($message);$checks++;}
function denies(callable $operation,string $message): void {try{$operation();}catch(RuntimeException|InvalidArgumentException $e){expect(true,$message);return;}throw new RuntimeException('Expected denial: '.$message);}
function manual_staff(string $name,array $permissions,int $event): array {global $db;$db->prepare("INSERT INTO users(username,password_hash,role,email,active,display_name,permissions,modules,event_scope,must_change_password) VALUES(?,?,'COORDINATOR',?,1,?,?,'[]','assigned',0)")->execute([$name,password_hash('Test-Payment-2026!',PASSWORD_DEFAULT),$name.'@example.invalid',$name,json_encode($permissions)]);$id=(int)$db->lastInsertId();$db->prepare('INSERT INTO st_event_assignments(user_id,event_id,assigned_by,assigned_at) VALUES(?,?,1,?)')->execute([$id,$event,gmdate('c')]);return st_finance_query($db,'SELECT * FROM users WHERE id=?',[$id])[0];}
function new_manual_participant100(): array {global $db;$email='manual-'.bin2hex(random_bytes(6)).'@example.invalid';$db->prepare('INSERT INTO az_participants(name,email,email_verified,profile_completed,created_at) VALUES(?,?,1,1,?)')->execute(['Manual Participant',$email,gmdate('c')]);return $db->query('SELECT * FROM az_participants ORDER BY id DESC LIMIT 1')->fetch();}
function pending(array $order,string $reference): void {global $db;$db->prepare("UPDATE az_orders SET state='PENDING_REVIEW',expires_at=2147483647 WHERE id=?")->execute([$order['id']]);$db->prepare("INSERT INTO az_payment_proofs(order_id,filename,mime,size_bytes,sha256,reference,paid_on,uploaded_at) VALUES(?,?,'image/png',1,?,?,?,?)")->execute([$order['id'],bin2hex(random_bytes(24)).'.png',str_repeat('a',64),$reference,date('Y-m-d'),gmdate('c')]);$proof=(int)$db->lastInsertId();$payment=az_manual_payment((int)$order['id']);$db->prepare("UPDATE az_manual_payments SET status='PENDING_REVIEW',reference=?,reference_key=?,paid_on=?,proof_id=?,revision=revision+1 WHERE order_id=?")->execute([$reference,az_reference_key(json_decode($payment['method_snapshot'],true),$reference),date('Y-m-d'),$proof,$order['id']]);}
function approval(int $id): array {$p=az_manual_payment($id);return ['revision'=>$p['revision'],'received_amount'=>number_format(az_order($id)['amount']/100,2,'.',''),'bank_confirmed'=>'yes','note'=>'Credit verified in receiving account'];}

$db->exec("UPDATE users SET must_change_password=0 WHERE role='SUPERADMIN'");$master=$db->query("SELECT * FROM users WHERE role='SUPERADMIN'")->fetch();
$events=$db->query("SELECT id FROM cms_content WHERE type='event' AND slug IN ('tulika','goc') ORDER BY id LIMIT 2")->fetchAll(PDO::FETCH_COLUMN);[$event1,$event2]=array_map('intval',$events);
$fields=cms_record($event1)['fields'];$fields['registration_mode']='open';$fields['form_workflow']='0';$fields['registration_url']='';$fields['game_categories']='[]';$fields['registration_opens']='';$fields['registration_closes']='';
$fields['ticket_types']=json_encode([['id'=>'paid','label'=>'Event pass','price'=>12550,'capacity'=>1,'active'=>true],['id'=>'free','label'=>'Free pass','price'=>0,'capacity'=>1,'active'=>true]]);
$fields['payment_methods']=az_validate_payment_methods([['id'=>'upi-one','label'=>'Coordinator UPI','kind'=>'upi','recipient'=>'QA Coordinator','upi'=>'qa@bank','active'=>1],['id'=>'bank-one','label'=>'Bank transfer','kind'=>'bank','recipient'=>'QA Coordinator','bank'=>'QA Bank','account'=>'12345678','ifsc'=>'ABCD0123456','active'=>1]]);
$fields['registration_form']=az_validate_registration_fields([['id'=>'team','label'=>'Team name','type'=>'text','required'=>1],['id'=>'format','label'=>'Format','type'=>'select','required'=>1,'options'=>"Solo\nTeam"],['id'=>'consent','label'=>'Rules accepted','type'=>'checkbox','required'=>1]]);
$db->prepare("UPDATE cms_content SET data=?,status='PUBLISHED' WHERE id=?")->execute([json_encode($fields),$event1]);$event=cms_record($event1);
$db->prepare('INSERT INTO az_participants(name,email,password_hash,email_verified,created_at) VALUES(?,?,?,1,?)')->execute(['Participant','manual@example.invalid',password_hash('Participant-2026!',PASSWORD_DEFAULT),gmdate('c')]);$participant=$db->query('SELECT * FROM az_participants ORDER BY id DESC LIMIT 1')->fetch();
$reviewer=manual_staff('reviewer',['payments.view','payments.verify','tickets.view','tickets.revoke','tickets.scan','finance.view'],$event1);
$other=manual_staff('other',['payments.view','payments.verify','tickets.revoke','finance.view'],$event2);
$readOnly=manual_staff('readonly',['payments.view'],$event1);
$answers=['team'=>'Clear code','format'=>'Team','consent'=>'yes'];
denies(fn()=>az_create_order(new_manual_participant100(),$event['slug'],'paid',1,$answers,'missing'),'Payment method belongs to this event');
denies(fn()=>az_create_order(new_manual_participant100(),$event['slug'],'paid',1,['team'=>'x'],'upi-one'),'Required custom fields enforced');
denies(fn()=>az_validate_payment_methods([['label'=>'Invalid','kind'=>'bank','recipient'=>'x','account'=>'abc','bank'=>'x','ifsc'=>'bad']]),'Invalid bank details rejected');
denies(fn()=>az_validate_registration_fields([['label'=>'Same','type'=>'text'],['label'=>'same','type'=>'text']]),'Duplicate labels rejected');
$order=az_create_order(new_manual_participant100(),$event['slug'],'paid',1,$answers,'upi-one');
expect($order['state']==='AWAITING_PROOF'&&$order['provider']==='manual'&&$order['environment']==='live','Manual pending order saved without gateway');
expect((int)$db->query('SELECT COUNT(*) FROM az_tickets')->fetchColumn()===0,'No ticket before bank confirmation');
expect(az_reserved($event1,'paid','live')===1,'New registrations reserve capacity');
$snapshot=json_decode(az_manual_payment((int)$order['id'])['method_snapshot'],true);$fields['payment_methods']=str_replace('qa@bank','changed@bank',$fields['payment_methods']);$db->prepare('UPDATE cms_content SET data=? WHERE id=?')->execute([json_encode($fields),$event1]);expect($snapshot['upi']==='qa@bank','Receiving account is frozen on order');
pending($order,'UTR123456');$id=(int)$order['id'];
denies(fn()=>az_review_manual_payment($other,$id,'approve',approval($id)),'Another event cannot approve');
denies(fn()=>az_review_manual_payment($readOnly,$id,'approve',approval($id)),'View permission cannot approve');
denies(fn()=>az_review_manual_payment($reviewer,$id,'approve',array_replace(approval($id),['bank_confirmed'=>''])),'Bank confirmation required');
denies(fn()=>az_review_manual_payment($reviewer,$id,'approve',array_replace(approval($id),['received_amount'=>'1'])),'Exact received amount required');
denies(fn()=>az_review_manual_payment($reviewer,$id,'approve',array_replace(approval($id),['revision'=>0])),'Stale review rejected');
az_review_manual_payment($reviewer,$id,'approve',approval($id));az_review_manual_payment($reviewer,$id,'approve',approval($id));
$ticket=$db->query('SELECT * FROM az_tickets ORDER BY id LIMIT 1')->fetch();expect((int)$db->query('SELECT COUNT(*) FROM az_tickets')->fetchColumn()===1,'Approval replay issues tickets once');
$summary=st_finance_summary($reviewer,$event1);expect($summary['gross']===12550&&$summary['direct_receipts']===12550&&$summary['unsettled_gross']===0,'Confirmed manual receipts counted once and never unsettled gateway money');
denies(fn()=>az_block_ticket($other,(int)$ticket['id'],true,'Wrong event'),'Block scoped to ticket parent order');
az_block_ticket($reviewer,(int)$ticket['id'],true,'Await committee review');denies(fn()=>az_scan($ticket['token'],$reviewer,true),'Blocked ticket denied entry');
az_block_ticket($reviewer,(int)$ticket['id'],false,'Committee approved entry');expect(az_scan($ticket['token'],$reviewer,true)['status']==='USED','Unblocked ticket admits once');
az_block_ticket($reviewer,(int)$ticket['id'],true,'Post entry review');az_block_ticket($reviewer,(int)$ticket['id'],false,'Review complete');denies(fn()=>az_scan($ticket['token'],$reviewer,true),'Unblock restores USED instead of allowing second entry');
az_record_manual_refund($reviewer,$id,['amount'=>'25.50','reference'=>'REFUND0001','note'=>'Fee adjustment','refund_confirmed'=>'yes']);az_record_manual_refund($reviewer,$id,['amount'=>'25.50','reference'=>'REFUND0001','note'=>'Fee adjustment','refund_confirmed'=>'yes']);
expect(st_finance_summary($reviewer,$event1)['net_registration']===10000,'Partial refund idempotent and exact');
denies(fn()=>az_record_manual_refund($reviewer,$id,['amount'=>'101','reference'=>'REFUND0002','note'=>'Too much','refund_confirmed'=>'yes']),'Cannot refund more than received');
az_record_manual_refund($reviewer,$id,['amount'=>'100','reference'=>'REFUND0002','note'=>'Event cancelled','refund_confirmed'=>'yes']);expect(az_order($id)['state']==='REFUNDED','Full refund changes payment state');denies(fn()=>az_block_ticket($reviewer,(int)$ticket['id'],false,'Try restore'),'Refunded tickets cannot be restored');
$second=az_create_order(new_manual_participant100(),$event['slug'],'paid',1,$answers,'bank-one');pending($second,'UTR223456');
denies(fn()=>az_create_order(new_manual_participant100(),$event['slug'],'paid',1,$answers,'bank-one'),'Pending reviews reserve all capacity');
$reviewInput=['revision'=>az_manual_payment((int)$second['id'])['revision'],'note'=>'Reference does not match bank record'];az_review_manual_payment($reviewer,(int)$second['id'],'reject',$reviewInput);expect(az_reserved($event1,'paid','live')===0,'Correction frees places and retains proof history');
expect(az_manual_payment((int)$second['id'])['reference_key']===null,'Rejected evidence does not permanently claim an unconfirmed transaction');
$free=az_create_order(new_manual_participant100(),$event['slug'],'free',1,$answers,'');expect($free['state']==='PAID','Free registrations issue immediately');denies(fn()=>az_create_order(new_manual_participant100(),$event['slug'],'free',1,$answers,''),'Free capacity enforced');
$hold=az_create_order(new_manual_participant100(),$event['slug'],'paid',1,$answers,'bank-one');
denies(fn()=>st_finance_mutate($master,'close',['event_id'=>$event1,'environment'=>'live','request_key'=>bin2hex(random_bytes(24)),'note'=>'Too early']),'Active reservation blocks closeout');
$db->prepare('UPDATE az_orders SET expires_at=1 WHERE id=?')->execute([$hold['id']]);
$archive=st_finance_snapshot($db,$event1,'live');expect(count($archive['payments'])===3&&count($archive['payment_reviews'])===4&&count($archive['payment_proofs'])===2,'Archive contains all payment and evidence history');expect(isset($archive['orders'][0]['answers'],$archive['orders'][0]['snapshot'],$archive['tickets'][0]['reason']),'Archive includes form answers and ticket controls');
$late=az_create_order(new_manual_participant100(),$event['slug'],'paid',1,$answers,'bank-one');
$db->prepare('UPDATE az_orders SET expires_at=1 WHERE id=?')->execute([$late['id']]);
$replacement=az_create_order(new_manual_participant100(),$event['slug'],'paid',1,$answers,'bank-one');pending($replacement,'UTR-LATE-REPLACEMENT');az_review_manual_payment($reviewer,(int)$replacement['id'],'approve',approval((int)$replacement['id']));
pending($late,'UTR-LATE-EXPIRED');$db->prepare('UPDATE az_orders SET expires_at=0 WHERE id=?')->execute([$late['id']]);
$before=(int)$db->query('SELECT COUNT(*) FROM az_tickets')->fetchColumn();az_review_manual_payment($reviewer,(int)$late['id'],'approve',approval((int)$late['id']));
expect(az_order((int)$late['id'])['state']==='PAID_REVIEW'&&(int)$db->query('SELECT COUNT(*) FROM az_tickets')->fetchColumn()===$before,'Late confirmed money cannot oversell an event');
expect(st_finance_summary($reviewer,$event1)['gross']===37650,'Capacity review keeps actual receipts in finance');
denies(fn()=>az_review_manual_payment($reviewer,(int)$late['id'],'reject',['revision'=>az_manual_payment((int)$late['id'])['revision'],'note'=>'Try reversing confirmed credit']),'Confirmed money cannot be rejected');
$fields['ticket_types']=str_replace('"capacity":1','"capacity":2',$fields['ticket_types']);$db->prepare('UPDATE cms_content SET data=? WHERE id=?')->execute([json_encode($fields),$event1]);
az_review_manual_payment($reviewer,(int)$late['id'],'approve',approval((int)$late['id']));expect(az_order((int)$late['id'])['state']==='PAID'&&(int)$db->query('SELECT COUNT(*) FROM az_tickets')->fetchColumn()===$before+1,'Capacity resolution releases the held ticket once');
az_reconcile_event_receipts($reviewer,$event1,['statement_date'=>(new DateTimeImmutable('today',new DateTimeZone('Asia/Kolkata')))->format('Y-m-d'),'bank_total'=>'251.00','reference'=>'BANK-COMPARE-1','note'=>'Event credits minus refunds']);expect((int)$db->query('SELECT difference FROM az_event_reconciliations ORDER BY id DESC LIMIT 1')->fetchColumn()===0,'Event bank comparison subtracts recorded refunds');
st_finance_mutate($master,'close',['event_id'=>$event1,'environment'=>'live','request_key'=>bin2hex(random_bytes(24)),'note'=>'Final event records checked']);
denies(fn()=>az_create_order(new_manual_participant100(),$event['slug'],'paid',1,$answers,'bank-one'),'Closed event rejects new registrations');
denies(fn()=>az_record_manual_refund($reviewer,(int)$late['id'],['amount'=>'1','reference'=>'CLOSED-REFUND','note'=>'Try closed changes','refund_confirmed'=>'yes']),'Closed finance cannot record refunds');
$db->prepare('UPDATE users SET session_version=session_version+1 WHERE id=?')->execute([$reviewer['id']]);denies(fn()=>az_review_manual_payment($reviewer,(int)$second['id'],'approve',approval((int)$second['id'])),'Revoked staff sessions denied under lock');
echo "PASS $checks manual payment and ticket invariants.\n";
