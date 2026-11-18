<?php
declare(strict_types=1);

function az_install_manual_payments(PDO $db): void {
    if($db->query("SELECT value FROM cms_settings WHERE setting_key='manual_payment_schema'")->fetchColumn()==='1')return;
    $sqlite=$db->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite';
    $id=$sqlite?'INTEGER PRIMARY KEY AUTOINCREMENT':'INT AUTO_INCREMENT PRIMARY KEY';$text=$sqlite?'TEXT':'MEDIUMTEXT';
    $db->exec("CREATE TABLE IF NOT EXISTS az_manual_payments (
        order_id INT PRIMARY KEY,method_snapshot $text NOT NULL,reference VARCHAR(100),reference_key VARCHAR(64) UNIQUE,
        paid_on VARCHAR(10),proof_id INT,status VARCHAR(20) NOT NULL DEFAULT 'AWAITING_PROOF',revision INT NOT NULL DEFAULT 1,
        reviewed_by INT,reviewed_at VARCHAR(40),review_note $text,received_amount INT NOT NULL DEFAULT 0,created_at VARCHAR(40) NOT NULL
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS az_payment_proofs (
        id $id,order_id INT NOT NULL,filename VARCHAR(100) NOT NULL UNIQUE,mime VARCHAR(40) NOT NULL,size_bytes INT NOT NULL,
        sha256 VARCHAR(64) NOT NULL,reference VARCHAR(100) NOT NULL,paid_on VARCHAR(10) NOT NULL,uploaded_at VARCHAR(40) NOT NULL
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS az_payment_reviews (
        id $id,order_id INT NOT NULL,staff_id INT NOT NULL,action VARCHAR(30) NOT NULL,proof_id INT,note $text NOT NULL,created_at VARCHAR(40) NOT NULL
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS az_ticket_blocks (
        ticket_id INT PRIMARY KEY,previous_status VARCHAR(20) NOT NULL,reason $text NOT NULL,blocked_by INT NOT NULL,
        blocked_at VARCHAR(40) NOT NULL,unblocked_by INT,unblocked_at VARCHAR(40)
    )");
    foreach(['az_proof_order'=>'az_payment_proofs(order_id,id)','az_review_order'=>'az_payment_reviews(order_id,id)'] as $name=>$definition){
        try{$db->exec('CREATE INDEX '.($sqlite?'IF NOT EXISTS ':'').$name.' ON '.$definition);}
        catch(PDOException $error){if((int)($error->errorInfo[1]??0)!==1061)throw $error;}
    }
    az_schema_marker($db,'manual_payment_schema');
}

function az_schema_marker(PDO $db,string $key): void {
    $insert=$db->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite'?'INSERT OR IGNORE':'INSERT IGNORE';
    $db->prepare($insert.' INTO cms_settings(setting_key,value) VALUES(?,?)')->execute([$key,'1']);
}

function az_payment_methods(array $event,bool $activeOnly=true): array {
    $methods=json_decode($event['payment_methods']??'[]',true)?:[];
    return array_values(array_filter($methods,fn($method)=>!$activeOnly||!empty($method['active'])));
}

function az_validate_payment_methods(mixed $rows): string {
    if(!is_array($rows)||count($rows)>10)throw new InvalidArgumentException('Use up to 10 payment methods per event.');
    $methods=[];$ids=[];
    foreach($rows as $row){
        if(!is_array($row))throw new InvalidArgumentException('Invalid payment method.');
        $label=az_setup_text($row,'label',80);if($label==='')continue;
        $method=['id'=>az_setup_text($row,'id',60)?:'method-'.bin2hex(random_bytes(6)),'label'=>$label];
        if(!preg_match('/^[a-z0-9-]{3,60}$/D',$method['id'])||isset($ids[$method['id']]))throw new InvalidArgumentException('Reload the payment editor before saving.');
        foreach(['kind'=>20,'recipient'=>120,'upi'=>100,'account'=>40,'ifsc'=>20,'bank'=>100,'instructions'=>2000,'qr'=>500] as $key=>$limit)$method[$key]=az_setup_text($row,$key,$limit);
        if(!in_array($method['kind'],['upi','bank','other'],true)||$method['recipient']==='')throw new InvalidArgumentException('Choose a payment type and enter the account holder.');
        if($method['kind']==='upi'&&!preg_match('/^[a-zA-Z0-9._-]{2,80}@[a-zA-Z0-9.-]{2,30}$/D',$method['upi']))throw new InvalidArgumentException('Enter a valid UPI ID.');
        if($method['kind']==='bank'&&(!preg_match('/^[0-9]{6,40}$/D',$method['account'])||!preg_match('/^[A-Z]{4}0[A-Z0-9]{6}$/D',strtoupper($method['ifsc']))||$method['bank']===''))throw new InvalidArgumentException('Enter the bank name, account number and valid IFSC.');
        if($method['kind']==='other'&&$method['instructions']==='')throw new InvalidArgumentException('Add payment instructions for this method.');
        if($method['qr']!==''&&!cms_valid_media($method['qr'],'image'))throw new InvalidArgumentException('Choose a QR image from the media library.');
        $method['ifsc']=strtoupper($method['ifsc']);$method['active']=isset($row['active']);
        $ids[$method['id']]=true;$methods[]=$method;
    }
    return json_encode($methods,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
}

function az_manual_payment(int $orderId): ?array {
    $query=cms_db()->prepare('SELECT * FROM az_manual_payments WHERE order_id=?');$query->execute([$orderId]);return $query->fetch()?:null;
}

function az_create_manual_order(array $participant,string $slug,string $typeId,int $quantity,array $answers,string $methodId,string $gameId=''): array {
    if(!$participant['email_verified'])throw new RuntimeException('Verify your email before registering.');
    if($quantity!==1)throw new InvalidArgumentException('Each registration has exactly one ticket.');
    az_limit('checkout',(string)$participant['id'],20,900);
    $db=cms_db();$db->beginTransaction();
    try{
        az_lock($db);
        $query=$db->prepare('SELECT * FROM az_participants WHERE id=? AND active=1 AND email_verified=1');$query->execute([$participant['id']]);$current=$query->fetch();
        if(!$current||(int)$current['session_version']!==(int)$participant['session_version'])throw new RuntimeException('Your account changed. Sign in again.');
        $event=az_event($slug);
        if(!$event||cms_event_phase($event['fields'])!=='open')throw new RuntimeException('Registration is closed for this event.');
        if(az_participation_mode($event)!=='registration')throw new RuntimeException('Use the contribution form for this event.');
        if($saved=az_existing_event_order((int)$current['id'],(int)$event['id'],$gameId))throw new RuntimeException(az_duplicate_registration_message($saved));
        $fields=$event['fields'];$game=az_selected_game($fields,$gameId);az_require_internal_registration97($fields,$gameId);$fields=az_game_fields81($fields,$gameId);$type=null;
        $performer=az_participation_mode($fields)==='performers';
        if(!$performer)st_finance_open($db,(int)$event['id'],'live');
        if($performer){
            if($quantity!==1||$typeId!=='performer-pass'||$methodId!==''||$gameId!=='')throw new InvalidArgumentException('Submit one free performer application using your own account.');
            $previous=$db->prepare("SELECT * FROM az_orders WHERE participant_id=? AND event_id=? AND ticket_type='performer-pass' AND provider='free' ORDER BY id DESC LIMIT 1");$previous->execute([$current['id'],$event['id']]);
            if($saved=$previous->fetch()){$db->commit();return $saved;}
        }
        $type=az_registration_entry($fields,$gameId,$typeId);if($type)$typeId=$type['id'];
        if(!$type)throw new RuntimeException('This pass is unavailable.');
        if(!empty($type['game'])&&$type['game']!==($game['id']??''))throw new RuntimeException('Choose a pass for the selected game.');
        $method=null;
        if($type['price']>0){
            foreach(az_payment_methods($fields) as $option)if($option['id']===$methodId)$method=$option;
            if(!$method)throw new RuntimeException('Choose an available payment method for this event.');
        }
        if($type['capacity']>0&&az_reserved((int)$event['id'],$typeId,'live')+$quantity>$type['capacity'])throw new RuntimeException('There are not enough passes remaining.');
        $validated=az_registration_answers($fields,$answers,'registration',$gameId);$now=gmdate('c');$amount=(int)$type['price']*$quantity;
        $snapshot=['title'=>$event['title'],'type'=>$type['label'],'game_id'=>$game['id']??'','game'=>$game['label']??'','starts_at'=>$fields['starts_at'],'ends_at'=>$fields['ends_at'],'venue'=>$fields['venue']?:setting('venue'),'rules_pdf'=>$fields['rules_pdf'],'name'=>$current['name'],'email'=>$current['email'],'registration_form'=>az_public_registration_schema($fields)];
        $snapshot['people']=(int)($type['people']??1);$snapshot['category_description']=$type['description']??'';if($performer)$snapshot['participation']='performers';
        $db->prepare('INSERT INTO az_orders(public_id,participant_id,event_id,event_slug,ticket_type,snapshot,answers,quantity,unit_price,amount,state,environment,provider,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')->execute([
            'ORDER-'.strtoupper(bin2hex(random_bytes(8))),$current['id'],$event['id'],$slug,$typeId,json_encode($snapshot,JSON_THROW_ON_ERROR),json_encode($validated,JSON_THROW_ON_ERROR),$quantity,$type['price'],$amount,$performer?'PERFORMER_PENDING':($amount?'AWAITING_PROOF':'PAID'),'live',$amount?'manual':'free',time()+3600,$now,$now,
        ]);
        $id=(int)$db->lastInsertId();$order=az_order($id);
        if($amount)$db->prepare('INSERT INTO az_manual_payments(order_id,method_snapshot,created_at) VALUES(?,?,?)')->execute([$id,json_encode($method,JSON_THROW_ON_ERROR),$now]);
        elseif(!$performer)az_issue_tickets($order);
        $db->commit();return $order;
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
}

function az_proof_directory(): string {
    $directory=getenv('ANAZORI_PAYMENT_PROOF_DIR')?:dirname(__DIR__,2).'/anazori-private/payment-proofs';
    return az_private_directory90($directory);
}

/** Receipts stay outside the public media library and are served after an access check. */
function az_store_payment_proof(array $file): array {
    $extensions=['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp'];
    $info=az_validate_upload95($file,$extensions,5*1024*1024,30000000);$size=$info['size'];$mime=$info['mime'];
    $name=bin2hex(random_bytes(24)).'.'.$extensions[$mime];$path=az_proof_directory().DIRECTORY_SEPARATOR.$name;$hash=hash_file('sha256',$file['tmp_name']);
    if(!move_uploaded_file($file['tmp_name'],$path))throw new RuntimeException('The screenshot could not be saved.');
    @chmod($path,0600);return ['filename'=>$name,'path'=>$path,'mime'=>$mime,'size'=>$size,'sha256'=>$hash];
}

function az_reference_key(array $method,string $reference): string {
    $account=match($method['kind']){'upi'=>strtolower($method['upi']),'bank'=>$method['account'].'|'.$method['ifsc'],default=>mb_strtolower($method['recipient'].'|'.$method['label'])};
    return hash('sha256',$method['kind'].'|'.$account.'|'.strtoupper(preg_replace('/[ -]/','',$reference)));
}

function az_submit_payment_proof(array $participant,string $publicId,array $input,array $file): array {
    az_limit('payment-proof',(string)$participant['id'],10,900);
    $reference=az_setup_text($input,'reference',100);$date=az_calendar_date(az_setup_text($input,'paid_on',10));
    if(!preg_match('/^[A-Za-z0-9][A-Za-z0-9 -]{5,99}$/D',$reference))throw new InvalidArgumentException('Enter the transaction reference / UTR shown on your payment.');
    if(!$date||$date>new DateTimeImmutable('today',new DateTimeZone('Asia/Kolkata')))throw new InvalidArgumentException('Enter the actual payment date.');
    $stored=null;$db=cms_db();$db->beginTransaction();
    try{
        az_lock($db);$current=az_participant();$order=az_order_public($publicId);
        if(!$current||!$current['email_verified']||!$order||(int)$order['participant_id']!==(int)$current['id']||$order['provider']!=='manual')throw new RuntimeException('Registration unavailable.');
        $payment=az_manual_payment((int)$order['id']);
        if(in_array($order['state'],['PENDING_REVIEW','PAID','PAID_REVIEW','REFUNDED'],true)){ $db->commit();return $order; }
        if(!in_array($order['state'],['AWAITING_PROOF','REJECTED'],true))throw new RuntimeException('This registration cannot accept a screenshot.');
        if((int)($input['revision']??0)!==(int)$payment['revision'])throw new RuntimeException('This registration changed. Reload before uploading.');
        st_finance_open($db,(int)$order['event_id'],'live');
        $key=az_reference_key(json_decode($payment['method_snapshot'],true),$reference);
        $query=$db->prepare('SELECT order_id FROM az_manual_payments WHERE reference_key=? AND order_id<>?');$query->execute([$key,$order['id']]);
        if($query->fetchColumn())throw new RuntimeException('This transaction reference is already attached to another registration.');
        $stored=az_store_payment_proof($file);$now=gmdate('c');
        $db->prepare('INSERT INTO az_payment_proofs(order_id,filename,mime,size_bytes,sha256,reference,paid_on,uploaded_at) VALUES(?,?,?,?,?,?,?,?)')->execute([$order['id'],$stored['filename'],$stored['mime'],$stored['size'],$stored['sha256'],$reference,$date->format('Y-m-d'),$now]);$proof=(int)$db->lastInsertId();
        $db->prepare("UPDATE az_manual_payments SET reference=?,reference_key=?,paid_on=?,proof_id=?,status='PENDING_REVIEW',revision=revision+1,reviewed_by=NULL,reviewed_at=NULL WHERE order_id=?")->execute([$reference,$key,$date->format('Y-m-d'),$proof,$order['id']]);
        // An expired hold does not take a reserved place away from another applicant.
        $hold=(int)$order['expires_at']>time()?2147483647:0;
        $db->prepare("UPDATE az_orders SET state='PENDING_REVIEW',expires_at=?,updated_at=? WHERE id=?")->execute([$hold,$now,$order['id']]);
        az_notify_order89(az_order((int)$order['id']),'registration_received');
        $db->commit();return az_order((int)$order['id']);
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();if($stored&&is_file($stored['path']))unlink($stored['path']);throw $error;}
}

function az_review_manual_payment(array $actor,int $id,string $decision,array $input): array {
    if(!in_array($decision,['approve','reject'],true))throw new InvalidArgumentException('Choose approve or reject.');
    $note=az_setup_text($input,'note',1000);
    if($decision==='reject'&&mb_strlen($note)<3)throw new InvalidArgumentException('Explain why the screenshot needs correction.');
    $db=cms_db();$db->beginTransaction();
    try{
        az_lock($db);$actor=st_refresh_user($actor);$order=az_payment_actor_order($actor,$id);$payment=az_manual_payment($id);
        if($order['provider']!=='manual'||!$payment)throw new RuntimeException('This is not a screenshot payment.');
        if($decision==='approve'&&$order['state']==='PAID'&&$payment['status']==='APPROVED'){$db->commit();return $order;}
        if((int)($input['revision']??0)!==(int)$payment['revision'])throw new RuntimeException('Another coordinator changed this payment. Reload before reviewing.');
        if(!in_array($order['state'],['PENDING_REVIEW','PAID_REVIEW'],true)||!$payment['proof_id'])throw new RuntimeException('This payment is not awaiting review.');
        st_finance_open($db,(int)$order['event_id'],'live');
        $now=gmdate('c');$state='REJECTED';$status='REJECTED';$received=0;
        if($decision==='approve'){
            if(($input['bank_confirmed']??'')!=='yes')throw new RuntimeException('Confirm that the money reached the account shown on this registration.');
            $received=st_finance_amount(az_setup_text($input,'received_amount',20));
            if($received!==(int)$order['amount'])throw new RuntimeException('The received amount must match this registration. Request correction for a short payment.');
            $event=cms_record((int)$order['event_id']);$type=null;
            foreach(az_prices($event['fields']??[]) as $option)if($option['id']===$order['ticket_type'])$type=$option;
            $available=$type&&(!$type['capacity']||az_reserved((int)$order['event_id'],$order['ticket_type'],'live',$id)+(int)$order['quantity']<=$type['capacity']);
            $state=$available?'PAID':'PAID_REVIEW';$status='APPROVED';
            $db->prepare("UPDATE az_orders SET state=?,provider_state='coordinator_confirmed',updated_at=? WHERE id=?")->execute([$state,$now,$id]);
            if($available)az_issue_tickets(az_order($id));
        }else{
            if($payment['status']==='APPROVED')throw new RuntimeException('Confirmed money cannot be rejected. Record an actual refund instead.');
            $db->prepare("UPDATE az_orders SET state='REJECTED',expires_at=0,updated_at=? WHERE id=?")->execute([$now,$id]);
        }
        // Rejected evidence keeps its history but does not claim a transaction forever.
        $db->prepare("UPDATE az_manual_payments SET status=?,review_note=?,reviewed_by=?,reviewed_at=?,received_amount=?,reference_key=CASE WHEN ?='REJECTED' THEN NULL ELSE reference_key END,revision=revision+1 WHERE order_id=?")->execute([$status,$note,$actor['id'],$now,$received,$status,$id]);
        $db->prepare('INSERT INTO az_payment_reviews(order_id,staff_id,action,proof_id,note,created_at) VALUES(?,?,?,?,?,?)')->execute([$id,$actor['id'],$decision,$payment['proof_id'],$note,$now]);
        st_event_audit($actor,(int)$order['event_id'],'payment.'.$decision,$order['public_id'].' · '.$state);
        st_finance_audit($db,$actor,'payment_'.$decision,(int)$order['event_id'],'live',['order'=>$order['public_id'],'proof_id'=>$payment['proof_id'],'amount'=>$received,'note'=>$note]);
        if($state==='REJECTED')az_notify_order89(az_order($id),'ticket_rejected','payment:'.((int)$payment['revision']+1),['note'=>$note,'rejection_type'=>'payment','payment_revision'=>(int)$payment['revision']+1,'path'=>'/payment-proof.php?order='.$order['public_id'],'cta'=>'Review payment details']);
        $db->commit();return az_order($id);
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
}

function az_block_ticket(array $actor,int $id,bool $blocked,string $reason): void {
    if(mb_strlen(trim($reason))<3||mb_strlen($reason)>1000)throw new InvalidArgumentException('Enter a reason for this ticket change.');
    $db=cms_db();$db->beginTransaction();
    try{
        az_lock($db);$actor=st_refresh_user($actor);
        if($actor['must_change_password']||!cms_can($actor,'tickets','revoke'))throw new RuntimeException('No ticket control access.');
        $ticket=st_require_ticket($actor,$id);$now=gmdate('c');
        if($blocked){
            if(!in_array($ticket['status'],['VALID','USED'],true))throw new RuntimeException('Only an issued, unblocked ticket can be blocked.');
            $query=$db->prepare('SELECT ticket_id FROM az_ticket_blocks WHERE ticket_id=?');$query->execute([$id]);
            if($query->fetchColumn())$db->prepare('UPDATE az_ticket_blocks SET previous_status=?,reason=?,blocked_by=?,blocked_at=?,unblocked_by=NULL,unblocked_at=NULL WHERE ticket_id=?')->execute([$ticket['status'],trim($reason),$actor['id'],$now,$id]);
            else $db->prepare('INSERT INTO az_ticket_blocks(ticket_id,previous_status,reason,blocked_by,blocked_at) VALUES(?,?,?,?,?)')->execute([$id,$ticket['status'],trim($reason),$actor['id'],$now]);
            $status='BLOCKED';
        }else{
            if($ticket['status']!=='BLOCKED'||$ticket['order_state']!=='PAID')throw new RuntimeException('Only a blocked ticket with a confirmed payment can be unblocked.');
            $query=$db->prepare('SELECT previous_status FROM az_ticket_blocks WHERE ticket_id=?');$query->execute([$id]);$status=$query->fetchColumn();
            if(!in_array($status,['VALID','USED'],true))throw new RuntimeException('The original ticket status is unavailable.');
            $db->prepare('UPDATE az_ticket_blocks SET unblocked_by=?,unblocked_at=? WHERE ticket_id=?')->execute([$actor['id'],$now,$id]);
        }
        $db->prepare('UPDATE az_tickets SET status=? WHERE id=?')->execute([$status,$id]);
        st_event_audit($actor,(int)$ticket['order_event_id'],$blocked?'ticket.block':'ticket.unblock',$ticket['ticket_id'].' · '.trim($reason));
        if($blocked)az_notify_order89(az_order((int)$ticket['order_id']),'ticket_rejected','block:'.$id.':'.hash('sha256',$now.'|'.trim($reason)),['note'=>trim($reason),'rejection_type'=>'ticket','ticket'=>$ticket['ticket_id'],'block_stamp'=>$now,'block_reason_hash'=>hash('sha256',trim($reason)),'path'=>'/ticket.php?id='.$ticket['ticket_id'],'cta'=>'View ticket status']);
        $db->commit();
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
}

function az_payment_proof_file(int $id): never {
    $query=cms_db()->prepare('SELECT p.*,o.participant_id,o.event_id FROM az_payment_proofs p JOIN az_orders o ON o.id=p.order_id WHERE p.id=?');$query->execute([$id]);$proof=$query->fetch();
    $participant=az_participant();$staff=cms_user();
    $owner=$proof&&$participant&&(int)$participant['id']===(int)$proof['participant_id'];
    $reviewer=$proof&&$staff&&!$staff['must_change_password']&&cms_can($staff,'payments','view')&&st_can_event($staff,(int)$proof['event_id']);
    if(!$proof||!($owner||$reviewer)||!preg_match('/^[a-f0-9]{48}\.(jpg|png|webp)$/D',$proof['filename'])){http_response_code(404);exit('Screenshot unavailable.');}
    $path=az_proof_directory().DIRECTORY_SEPARATOR.$proof['filename'];
    if(!az_private_file_safe95($path,az_proof_directory())||!hash_equals($proof['sha256'],hash_file('sha256',$path))){http_response_code(404);exit('Screenshot unavailable.');}
    header('Cross-Origin-Resource-Policy: same-origin');header('Content-Type: '.$proof['mime']);header('X-Content-Type-Options: nosniff');header('Cache-Control: private, no-store');header("Content-Security-Policy: default-src 'none'; sandbox");
    header('Content-Disposition: inline; filename="payment-screenshot.'.pathinfo($proof['filename'],PATHINFO_EXTENSION).'"');header('Content-Length: '.filesize($path));readfile($path);exit;
}

function az_payment_state_label(string $state): string {
    return ['FORM_PENDING'=>'Awaiting coordinator approval','FORM_CORRECTION'=>'Response correction requested','FORM_DECLINED'=>'Application declined','PERFORMER_PENDING'=>'Awaiting performer confirmation','PERFORMER_DECLINED'=>'Performance not selected','AWAITING_PROOF'=>'Upload payment screenshot','PENDING_REVIEW'=>'Awaiting coordinator review','REJECTED'=>'Correction requested','PAID'=>'Confirmed','PAID_REVIEW'=>'Approved · ticket capacity review','REFUNDED'=>'Refund recorded'][$state]??ucwords(strtolower(str_replace('_',' ',$state)));
}

function az_record_date_label(string $timestamp): string {
    try{return (new DateTimeImmutable($timestamp))->setTimezone(new DateTimeZone('Asia/Kolkata'))->format('d M Y · g:i a').' IST';}
    catch(Exception $error){return $timestamp;}
}
