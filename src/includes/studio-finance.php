<?php
declare(strict_types=1);

/** Event accounting uses integer paise. This journal records organiser actions;
 * confirmed registrations and actual refunds remain in az_orders/az_refunds. */
function st_install_finance(PDO $db): void {
    if($db->query("SELECT value FROM cms_settings WHERE setting_key='studio_finance_schema'")->fetchColumn()==='3')return;
    $sqlite=$db->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite';
    $id=$sqlite?'INTEGER PRIMARY KEY AUTOINCREMENT':'INT AUTO_INCREMENT PRIMARY KEY';
    $text=$sqlite?'TEXT':'MEDIUMTEXT';
    foreach([
        "st_budgets (event_id INT NOT NULL,environment VARCHAR(10) NOT NULL,allocated BIGINT NOT NULL DEFAULT 0,revision INT NOT NULL DEFAULT 1,closed INT NOT NULL DEFAULT 0,updated_by INT NOT NULL,updated_at VARCHAR(40) NOT NULL,PRIMARY KEY(event_id,environment))",
        "st_expenses (id $id,event_id INT NOT NULL,environment VARCHAR(10) NOT NULL,title VARCHAR(180) NOT NULL,category VARCHAR(40) NOT NULL,payee VARCHAR(150) NOT NULL,amount BIGINT NOT NULL,description $text NOT NULL,invoice_reference VARCHAR(150) NOT NULL,proof_evidence_id INT,created_by INT NOT NULL,status VARCHAR(20) NOT NULL DEFAULT 'DRAFT',revision INT NOT NULL DEFAULT 1,reviewed_by INT,review_note VARCHAR(500),paid_by INT,payment_reference VARCHAR(150),created_at VARCHAR(40) NOT NULL,updated_at VARCHAR(40) NOT NULL)",
        "st_finance_evidence (id $id,event_id INT NOT NULL,environment VARCHAR(10) NOT NULL,filename VARCHAR(100) NOT NULL UNIQUE,title VARCHAR(180) NOT NULL,mime VARCHAR(100) NOT NULL,size_bytes INT NOT NULL,sha256 VARCHAR(64) NOT NULL,uploaded_by INT NOT NULL,created_at VARCHAR(40) NOT NULL)",
        "st_finance_ledger (id $id,event_id INT NOT NULL,environment VARCHAR(10) NOT NULL,kind VARCHAR(30) NOT NULL,amount BIGINT NOT NULL,title VARCHAR(180) NOT NULL,reference VARCHAR(150) NOT NULL,source_id INT,reverses_id INT UNIQUE,created_by INT NOT NULL,created_at VARCHAR(40) NOT NULL)",
        "st_settlements (id $id,environment VARCHAR(10) NOT NULL,provider VARCHAR(20) NOT NULL,reference VARCHAR(150) NOT NULL,gross BIGINT NOT NULL,refunds BIGINT NOT NULL,fees BIGINT NOT NULL,net BIGINT NOT NULL,bank_date VARCHAR(10) NOT NULL,bank_reference VARCHAR(150) NOT NULL,created_by INT NOT NULL,created_at VARCHAR(40) NOT NULL,UNIQUE(environment,provider,reference))",
        "st_settlement_orders (settlement_id INT NOT NULL,order_id INT NOT NULL UNIQUE,gross BIGINT NOT NULL,refunds BIGINT NOT NULL,fees BIGINT NOT NULL DEFAULT 0,PRIMARY KEY(settlement_id,order_id))",
        "st_reconciliations (id $id,environment VARCHAR(10) NOT NULL,statement_date VARCHAR(10) NOT NULL,bank_total BIGINT NOT NULL,recorded_total BIGINT NOT NULL,difference BIGINT NOT NULL,reference VARCHAR(150) NOT NULL,note VARCHAR(1000) NOT NULL,created_by INT NOT NULL,created_at VARCHAR(40) NOT NULL)",
        "st_closeouts (id $id,event_id INT NOT NULL,environment VARCHAR(10) NOT NULL,snapshot $text NOT NULL,snapshot_hash VARCHAR(64) NOT NULL,note VARCHAR(1000) NOT NULL,created_by INT NOT NULL,created_at VARCHAR(40) NOT NULL)",
        "st_finance_commands (request_key VARCHAR(64) PRIMARY KEY,user_id INT NOT NULL,action VARCHAR(60) NOT NULL,input_hash VARCHAR(64) NOT NULL,result_id INT NOT NULL DEFAULT 0,created_at VARCHAR(40) NOT NULL)",
        "st_finance_audit (id $id,event_id INT,environment VARCHAR(10) NOT NULL,user_id INT NOT NULL,action VARCHAR(60) NOT NULL,detail $text NOT NULL,created_at VARCHAR(40) NOT NULL)",
    ] as $definition) $db->exec('CREATE TABLE IF NOT EXISTS '.$definition);
    $columns=$sqlite?array_column($db->query('PRAGMA table_info(st_expenses)')->fetchAll(),'name'):array_column($db->query('SHOW COLUMNS FROM st_expenses')->fetchAll(),'Field');
    if(!in_array('proof_evidence_id',$columns,true)){
        try{$db->exec('ALTER TABLE st_expenses ADD COLUMN proof_evidence_id INT');}catch(PDOException $e){$current=$sqlite?array_column($db->query('PRAGMA table_info(st_expenses)')->fetchAll(),'name'):array_column($db->query('SHOW COLUMNS FROM st_expenses')->fetchAll(),'Field');if(!in_array('proof_evidence_id',$current,true))throw $e;}
    }
    $settlementColumns=$sqlite?array_column($db->query('PRAGMA table_info(st_settlement_orders)')->fetchAll(),'name'):array_column($db->query('SHOW COLUMNS FROM st_settlement_orders')->fetchAll(),'Field');
    if(!in_array('fees',$settlementColumns,true)){
        try{$db->exec('ALTER TABLE st_settlement_orders ADD COLUMN fees BIGINT NOT NULL DEFAULT 0');}catch(PDOException $e){$current=$sqlite?array_column($db->query('PRAGMA table_info(st_settlement_orders)')->fetchAll(),'name'):array_column($db->query('SHOW COLUMNS FROM st_settlement_orders')->fetchAll(),'Field');if(!in_array('fees',$current,true))throw $e;}
        foreach(st_finance_query($db,'SELECT id,fees FROM st_settlements ORDER BY id') as $batch){$rows=st_finance_query($db,'SELECT order_id,gross FROM st_settlement_orders WHERE settlement_id=? ORDER BY order_id',[$batch['id']]);$allocation=st_finance_allocate_fees((int)$batch['fees'],$rows);foreach($allocation as $orderId=>$fee)$db->prepare('UPDATE st_settlement_orders SET fees=? WHERE order_id=?')->execute([$fee,$orderId]);}
    }
    foreach(['st_expenses_scope'=>'st_expenses(event_id,environment,status,id)','st_ledger_scope'=>'st_finance_ledger(event_id,environment,id)','st_audit_scope'=>'st_finance_audit(event_id,environment,id)','st_closeouts_scope'=>'st_closeouts(event_id,environment,id)'] as $name=>$definition){
        try{$db->exec('CREATE INDEX '.($sqlite?'IF NOT EXISTS ':'').$name.' ON '.$definition);}catch(PDOException $e){if((int)($e->errorInfo[1]??0)!==1061)throw $e;}
    }
    $marker=$db->prepare('SELECT value FROM cms_settings WHERE setting_key=?');$marker->execute(['studio_finance_schema']);
    if($marker->fetchColumn()===false){try{$db->prepare('INSERT INTO cms_settings(setting_key,value) VALUES(?,?)')->execute(['studio_finance_schema','3']);}catch(PDOException $e){$marker->execute(['studio_finance_schema']);if($marker->fetchColumn()===false)throw $e;$db->prepare('UPDATE cms_settings SET value=? WHERE setting_key=?')->execute(['3','studio_finance_schema']);}}
    else $db->prepare('UPDATE cms_settings SET value=? WHERE setting_key=?')->execute(['3','studio_finance_schema']);
}

function st_finance_permission(array $u,string $action,bool $global=false): void {
    if(!empty($u['must_change_password']))throw new RuntimeException('Set your own password before using financial records.');
    if(!cms_can($u,'finance',$action)||($global&&st_event_ids($u)!==null)) throw new RuntimeException('This financial action requires an authorised '.($global?'festival finance':'event finance').' account.');
}
function st_finance_environment(string $environment): string {
    if(!in_array($environment,['live','test'],true))throw new InvalidArgumentException('Choose live or test accounting.');return $environment;
}
function st_finance_amount(string $value,bool $allowZero=false): int {
    if(!preg_match('/^(0|[1-9][0-9]{0,8})(?:\.([0-9]{1,2}))?$/D',trim($value),$m))throw new InvalidArgumentException('Enter a rupee amount with at most two decimal places.');
    $amount=((int)$m[1])*100+(int)str_pad($m[2]??'',2,'0');
    if(!$allowZero&&$amount===0)throw new InvalidArgumentException('The amount must be greater than zero.');return $amount;
}
function st_finance_input(array $input,string $key,int $max=500,bool $required=true): string {
    $value=$input[$key]??'';if(!is_string($value)||mb_strlen($value)>$max||str_contains($value,"\0"))throw new InvalidArgumentException('Check '.str_replace('_',' ',$key).'.');
    $value=trim($value);if($required&&$value==='')throw new InvalidArgumentException('Enter '.str_replace('_',' ',$key).'.');return $value;
}
function st_finance_id(array $input,string $key='id',bool $optional=false): int {
    $value=$input[$key]??'';if($optional&&($value===''||$value===null))return 0;
    if(!is_scalar($value)||!preg_match('/^[1-9][0-9]{0,9}$/D',(string)$value))throw new InvalidArgumentException('Choose a valid '.str_replace('_',' ',$key).'.');return (int)$value;
}
function st_finance_date(string $value): string {
    $d=DateTimeImmutable::createFromFormat('!Y-m-d',$value);if(!$d||$d->format('Y-m-d')!==$value)throw new InvalidArgumentException('Enter a valid date.');return $value;
}
function st_finance_event(array $u,int $eventId): void {
    st_require_event($u,$eventId);$event=cms_record($eventId);if(!$event||$event['type']!=='event')throw new InvalidArgumentException('Choose an existing event.');
}
function st_finance_query(PDO $db,string $sql,array $params=[]): array {$s=$db->prepare($sql);$s->execute($params);return $s->fetchAll();}
function st_finance_sum(PDO $db,string $sql,array $params=[]): int {$s=$db->prepare($sql);$s->execute($params);return (int)$s->fetchColumn();}
/** Exact product/division without an intermediate a*b overflow. */
function st_finance_ratio(int $a,int $b,int $denominator): array {
    if($a<0||$b<0||$denominator<=0)throw new InvalidArgumentException('Invalid fee allocation.');
    $quotient=intdiv($a,$denominator)*$b;$unit=$a%$denominator;$fraction=0;$whole=0;
    foreach(str_split(decbin($b)) as $bit){$whole*=2;$fraction*=2;if($bit==='1')$fraction+=$unit;$whole+=intdiv($fraction,$denominator);$fraction%=$denominator;}
    return [$quotient+$whole,$fraction];
}
function st_finance_allocate_fees(int $fees,array $orders): array {
    $gross=array_sum(array_map(fn($r)=>(int)$r['gross'],$orders));if(!$orders||$gross<=0||$fees<0||$fees>$gross)throw new InvalidArgumentException('Invalid settlement fee allocation.');
    $allocation=[];$remainders=[];$assigned=0;
    foreach($orders as $order){[$fee,$remainder]=st_finance_ratio($fees,(int)$order['gross'],$gross);$id=(int)$order['order_id'];$allocation[$id]=$fee;$assigned+=$fee;$remainders[]=['id'=>$id,'remainder'=>$remainder];}
    usort($remainders,fn($a,$b)=>($b['remainder']<=>$a['remainder'])?:($a['id']<=>$b['id']));
    for($i=0;$i<$fees-$assigned;$i++)$allocation[$remainders[$i]['id']]++;return $allocation;
}
function st_finance_scope(array $u,?int $eventId,string $column): array {
    if($eventId!==null){st_finance_event($u,$eventId);return ['sql'=>$column.'=?','params'=>[$eventId]];}return st_scope_sql($u,$column);
}
function st_finance_budget(PDO $db,int $eventId,string $environment): array {
    $rows=st_finance_query($db,'SELECT * FROM st_budgets WHERE event_id=? AND environment=?',[$eventId,$environment]);
    return $rows[0]??['event_id'=>$eventId,'environment'=>$environment,'allocated'=>0,'revision'=>0,'closed'=>0];
}
function st_finance_open(PDO $db,int $eventId,string $environment): void {
    if((int)st_finance_budget($db,$eventId,$environment)['closed'])throw new RuntimeException('This event accounting period is closed. Finance must reopen it with a reason before changes.');
}
function st_finance_reserved(PDO $db,int $eventId,string $environment): int {
    $approved=st_finance_sum($db,"SELECT COALESCE(SUM(amount),0) FROM st_expenses WHERE event_id=? AND environment=? AND status='APPROVED'",[$eventId,$environment]);
    $paid=-st_finance_sum($db,"SELECT COALESCE(SUM(amount),0) FROM st_finance_ledger WHERE event_id=? AND environment=? AND kind IN ('EXPENSE_PAYMENT','EXPENSE_REVERSAL')",[$eventId,$environment]);
    return $approved+$paid;
}
function st_finance_audit(PDO $db,array $u,string $action,?int $eventId,string $environment,array $details): void {
    $json=json_encode($details,JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE);
    $db->prepare('INSERT INTO st_finance_audit(event_id,environment,user_id,action,detail,created_at) VALUES(?,?,?,?,?,?)')->execute([$eventId,$environment,$u['id'],$action,$json,gmdate('c')]);
    cms_audit($u,'finance.'.$action,'Event '.($eventId??'festival').' · '.$environment.' · '.$json);
}
function st_finance_journal(PDO $db,array $u,int $eventId,string $environment,string $kind,int $amount,string $title,string $reference,?int $sourceId=null,?int $reversesId=null): int {
    $db->prepare('INSERT INTO st_finance_ledger(event_id,environment,kind,amount,title,reference,source_id,reverses_id,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)')->execute([$eventId,$environment,$kind,$amount,$title,$reference,$sourceId,$reversesId,$u['id'],gmdate('c')]);return (int)$db->lastInsertId();
}
function st_finance_evidence(PDO $db,array $u,int $id,int $eventId,string $environment): ?int {
    if(!$id)return null;$rows=st_finance_query($db,'SELECT * FROM st_finance_evidence WHERE id=?',[$id]);$row=$rows[0]??null;
    if(!$row||(int)$row['event_id']!==$eventId||$row['environment']!==$environment||(st_event_ids($u)!==null&&(int)$row['uploaded_by']!==(int)$u['id']))throw new InvalidArgumentException('Choose a private receipt for this event and accounting environment.');return $id;
}
function st_finance_evidence_dir(): string {
    $dir=getenv('ANAZORI_STUDIO_RECEIPT_PATH')?:dirname(__DIR__,2).'/anazori-private/studio-receipts';
    return az_private_directory90($dir);
}
function st_finance_receipt(array $u,int $id): void {
    st_finance_permission($u,'view');$rows=st_finance_query(cms_db(),'SELECT * FROM st_finance_evidence WHERE id=?',[$id]);$row=$rows[0]??null;if(!$row)throw new RuntimeException('Receipt unavailable.');st_finance_event($u,(int)$row['event_id']);
    if(!preg_match('/^[a-f0-9]{48}\.(pdf|jpg|png|webp)$/D',$row['filename']))throw new RuntimeException('Receipt unavailable.');$path=st_finance_evidence_dir().DIRECTORY_SEPARATOR.$row['filename'];
    if(!az_private_file_safe95($path,st_finance_evidence_dir())||!hash_equals($row['sha256'],hash_file('sha256',$path)))throw new RuntimeException('Receipt integrity check failed. Restore the original evidence from backup.');
    st_finance_audit(cms_db(),$u,'receipt_download',(int)$row['event_id'],$row['environment'],['receipt_id'=>$id]);
    header('Cross-Origin-Resource-Policy: same-origin');header("Content-Security-Policy: default-src 'none'; sandbox");header('Content-Type: '.$row['mime']);header('Content-Disposition: attachment; filename="anazori-receipt-'.$id.'.'.pathinfo($row['filename'],PATHINFO_EXTENSION).'"');header('Content-Length: '.filesize($path));header('Cache-Control: private, no-store');header('X-Content-Type-Options: nosniff');readfile($path);exit;
}

/** All scope and state checks are repeated inside the locked transaction. A
 * retried command returns its original result; a reused key with other input fails. */
function st_finance_mutate(array $u,string $action,array $input): int {
    $actions=['allocate','receipt_upload','expense_save','expense_submit','expense_approve','expense_reject','expense_void','expense_pay','expense_reverse','income_post','income_reverse','settlement_record','reconcile','close','reopen'];
    if(!in_array($action,$actions,true))throw new InvalidArgumentException('Unknown finance action.');
    $permission=match($action){'allocate'=>'allocate','receipt_upload','expense_save','expense_submit'=>'submit','expense_approve','expense_reject'=>'approve','expense_void'=>'view','close','reopen'=>'close',default=>'record'};
    $global=in_array($action,['allocate','expense_pay','expense_reverse','income_post','income_reverse','settlement_record','reconcile','close','reopen'],true);
    st_finance_permission($u,$permission,$global);
    if($action==='receipt_upload')az_limit('finance-upload',(string)$u['id'],30,900);
    $environment=st_finance_environment(st_finance_input($input,'environment',10));
    $key=st_finance_input($input,'request_key',64);if(!preg_match('/^[a-f0-9]{32,64}$/D',$key))throw new InvalidArgumentException('Reload the form before saving.');
    $payload=$input;unset($payload['csrf_token'],$payload['request_key'],$payload['action'],$payload['evidence_file']);ksort($payload);$hash=hash('sha256',json_encode($payload,JSON_THROW_ON_ERROR));
    $db=cms_db();$db->beginTransaction();
    $newEvidencePath=null;try{
        az_lock($db);
        // Re-read account access after acquiring the lock: permission revocation
        // cannot race a finance mutation that was started from a stale session.
        if(function_exists('st_refresh_user'))$u=st_refresh_user($u);
        st_finance_permission($u,$permission,$global);
        $previous=st_finance_query($db,'SELECT * FROM st_finance_commands WHERE request_key=?',[$key]);
        if($previous){
            $p=$previous[0];if((int)$p['user_id']!==(int)$u['id']||$p['action']!==$action||!hash_equals($p['input_hash'],$hash))throw new RuntimeException('This form was already used for another change. Reload it.');
            if(str_starts_with($action,'expense_')&&$action!=='expense_save'){$saved=st_finance_query($db,'SELECT event_id FROM st_expenses WHERE id=?',[st_finance_id($input)]);if(!$saved)throw new RuntimeException('This expense is unavailable.');st_finance_event($u,(int)$saved[0]['event_id']);}
            elseif($action==='income_reverse'){$saved=st_finance_query($db,'SELECT event_id FROM st_finance_ledger WHERE id=?',[st_finance_id($input)]);if(!$saved)throw new RuntimeException('This receipt is unavailable.');st_finance_event($u,(int)$saved[0]['event_id']);}
            elseif(!in_array($action,['settlement_record','reconcile'],true))st_finance_event($u,st_finance_id($input,'event_id'));
            $db->commit();return (int)$p['result_id'];
        }
        $eventId=null;$result=0;$details=[];$expense=null;
        if(str_starts_with($action,'expense_')&&$action!=='expense_save'){
            $id=st_finance_id($input);$rows=st_finance_query($db,'SELECT * FROM st_expenses WHERE id=?',[$id]);$expense=$rows[0]??null;
            if(!$expense||$expense['environment']!==$environment)throw new RuntimeException('This expense is unavailable.');$eventId=(int)$expense['event_id'];st_finance_event($u,$eventId);st_finance_open($db,$eventId,$environment);
            if((int)$expense['revision']!==st_finance_id($input,'revision'))throw new RuntimeException('This expense changed while you were reviewing it. Reload before saving.');$result=$id;
        }elseif(!in_array($action,['settlement_record','reconcile','income_reverse'],true)){
            $eventId=st_finance_id($input,'event_id');st_finance_event($u,$eventId);if($action!=='reopen')st_finance_open($db,$eventId,$environment);
        }
        $now=gmdate('c');
        switch($action){
            case 'receipt_upload':
                $file=$input['evidence_file']??null;if(!is_array($file)||($file['error']??UPLOAD_ERR_NO_FILE)!==UPLOAD_ERR_OK||!is_uploaded_file($file['tmp_name']??''))throw new InvalidArgumentException('Choose a receipt file to upload.');
                $extensions=['application/pdf'=>'pdf','image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp'];$info=az_validate_upload95($file,$extensions,12*1024*1024);$size=$info['size'];$mime=$info['mime'];
                $sha=hash_file('sha256',$file['tmp_name']);if(!hash_equals(st_finance_input($input,'evidence_hash',64),$sha))throw new RuntimeException('Receipt upload changed. Try again.');
                $filename=bin2hex(random_bytes(24)).'.'.$extensions[$mime];$newEvidencePath=st_finance_evidence_dir().DIRECTORY_SEPARATOR.$filename;if(!move_uploaded_file($file['tmp_name'],$newEvidencePath))throw new RuntimeException('Could not store the receipt securely.');@chmod($newEvidencePath,0600);
                $title=mb_substr(basename((string)$file['name']),0,180);$db->prepare('INSERT INTO st_finance_evidence(event_id,environment,filename,title,mime,size_bytes,sha256,uploaded_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)')->execute([$eventId,$environment,$filename,$title,$mime,$size,$sha,$u['id'],$now]);$result=(int)$db->lastInsertId();$details=['receipt_id'=>$result,'sha256'=>$sha,'size'=>$size];break;
            case 'allocate':
                $budget=st_finance_budget($db,$eventId,$environment);$revision=st_finance_input($input,'revision',12);if(!ctype_digit($revision)||(int)$revision!==(int)$budget['revision'])throw new RuntimeException('The allocation changed. Reload before saving.');
                $amount=st_finance_amount(st_finance_input($input,'amount',20),true);if($amount<st_finance_reserved($db,$eventId,$environment))throw new RuntimeException('Allocation cannot be lower than paid spending and approved commitments.');
                $note=st_finance_input($input,'note',500);
                if($budget['revision'])$db->prepare('UPDATE st_budgets SET allocated=?,revision=revision+1,updated_by=?,updated_at=? WHERE event_id=? AND environment=?')->execute([$amount,$u['id'],$now,$eventId,$environment]);
                else $db->prepare('INSERT INTO st_budgets(event_id,environment,allocated,updated_by,updated_at) VALUES(?,?,?,?,?)')->execute([$eventId,$environment,$amount,$u['id'],$now]);
                $details=['before'=>(int)$budget['allocated'],'after'=>$amount,'note'=>$note];$result=$eventId;break;
            case 'expense_save':
                $id=st_finance_id($input,'id',true);$title=st_finance_input($input,'title',180);$category=st_finance_input($input,'category',40);
                if(!in_array($category,['production','prizes','hospitality','travel','equipment','marketing','venue','other'],true))throw new InvalidArgumentException('Choose an expense category.');
                $payee=st_finance_input($input,'payee',150);$amount=st_finance_amount(st_finance_input($input,'amount',20));$description=st_finance_input($input,'description',2000);$invoice=st_finance_input($input,'invoice_reference',150);
                $proof=st_finance_evidence($db,$u,st_finance_id($input,'proof_evidence_id',true),$eventId,$environment);
                if($id){
                    $rows=st_finance_query($db,'SELECT * FROM st_expenses WHERE id=?',[$id]);$old=$rows[0]??null;
                    if(!$old||(int)$old['event_id']!==$eventId||$old['environment']!==$environment||!in_array($old['status'],['DRAFT','REJECTED'],true)||(int)$old['created_by']!==(int)$u['id'])throw new RuntimeException('Only your own draft or rejected expense can be edited.');
                    if((int)$old['revision']!==st_finance_id($input,'revision'))throw new RuntimeException('This expense changed. Reload it.');
                    $db->prepare("UPDATE st_expenses SET title=?,category=?,payee=?,amount=?,description=?,invoice_reference=?,proof_evidence_id=?,status='DRAFT',revision=revision+1,reviewed_by=NULL,review_note=NULL,updated_at=? WHERE id=?")->execute([$title,$category,$payee,$amount,$description,$invoice,$proof,$now,$id]);$result=$id;
                }else{
                    $db->prepare('INSERT INTO st_expenses(event_id,environment,title,category,payee,amount,description,invoice_reference,proof_evidence_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')->execute([$eventId,$environment,$title,$category,$payee,$amount,$description,$invoice,$proof,$u['id'],$now,$now]);$result=(int)$db->lastInsertId();
                }$details=['expense_id'=>$result,'amount'=>$amount,'invoice_reference'=>$invoice];break;
            case 'expense_submit':
                if((int)$expense['created_by']!==(int)$u['id']||$expense['status']!=='DRAFT')throw new RuntimeException('Only your own draft can be submitted.');
                $db->prepare("UPDATE st_expenses SET status='SUBMITTED',revision=revision+1,updated_at=? WHERE id=?")->execute([$now,$result]);$details=['expense_id'=>$result];break;
            case 'expense_approve': case 'expense_reject':
                if($expense['status']!=='SUBMITTED')throw new RuntimeException('Only submitted expenses can be reviewed.');
                if((int)$expense['created_by']===(int)$u['id'])throw new RuntimeException('An independent reviewer must review your expense.');
                $note=st_finance_input($input,'note',500);
                if($action==='expense_approve'&&(st_finance_reserved($db,$eventId,$environment)+(int)$expense['amount'])>(int)st_finance_budget($db,$eventId,$environment)['allocated'])throw new RuntimeException('Approval would exceed the event allocation. Increase the allocation or release another commitment first.');
                $status=$action==='expense_approve'?'APPROVED':'REJECTED';$db->prepare('UPDATE st_expenses SET status=?,revision=revision+1,reviewed_by=?,review_note=?,updated_at=? WHERE id=?')->execute([$status,$u['id'],$note,$now,$result]);$details=['expense_id'=>$result,'status'=>$status,'note'=>$note];break;
            case 'expense_void':
                if(!in_array($expense['status'],['DRAFT','REJECTED','SUBMITTED','APPROVED'],true))throw new RuntimeException('Paid or reversed expenses cannot be voided. Record an actual reversal instead.');
                if($expense['status']==='APPROVED'){st_finance_permission($u,'approve');if((int)$expense['created_by']===(int)$u['id'])throw new RuntimeException('An independent reviewer must release an approved expense.');}
                else{st_finance_permission($u,'submit');if((int)$expense['created_by']!==(int)$u['id'])throw new RuntimeException('Only the maker may withdraw this expense.');}
                $note=st_finance_input($input,'note',500);$db->prepare("UPDATE st_expenses SET status='VOID',revision=revision+1,review_note=?,updated_at=? WHERE id=?")->execute([$note,$now,$result]);$details=['expense_id'=>$result,'previous_status'=>$expense['status'],'note'=>$note];break;
            case 'expense_pay':
                if($expense['status']!=='APPROVED')throw new RuntimeException('Only approved expenses can be recorded as paid.');
                if((int)$expense['created_by']===(int)$u['id'])throw new RuntimeException('A different finance operator must record payment for your expense.');
                $reference=st_finance_input($input,'payment_reference',150);$db->prepare("UPDATE st_expenses SET status='PAID',revision=revision+1,paid_by=?,payment_reference=?,updated_at=? WHERE id=?")->execute([$u['id'],$reference,$now,$result]);
                st_finance_journal($db,$u,$eventId,$environment,'EXPENSE_PAYMENT',-(int)$expense['amount'],$expense['title'],$reference,$result);$details=['expense_id'=>$result,'amount'=>(int)$expense['amount'],'payment_reference'=>$reference];break;
            case 'expense_reverse':
                if($expense['status']!=='PAID')throw new RuntimeException('Only a paid expense may be reversed after money has actually been returned.');
                $reference=st_finance_input($input,'payment_reference',150);$note=st_finance_input($input,'note',500);$original=st_finance_query($db,"SELECT id FROM st_finance_ledger WHERE source_id=? AND kind='EXPENSE_PAYMENT'",[$result]);if(!$original)throw new RuntimeException('The original payment journal is missing.');
                $db->prepare("UPDATE st_expenses SET status='REVERSED',revision=revision+1,review_note=?,updated_at=? WHERE id=?")->execute([$note,$now,$result]);st_finance_journal($db,$u,$eventId,$environment,'EXPENSE_REVERSAL',(int)$expense['amount'],$expense['title'],$reference,$result,(int)$original[0]['id']);$details=['expense_id'=>$result,'returned_amount'=>(int)$expense['amount'],'return_reference'=>$reference,'note'=>$note];break;
            case 'income_post':
                $amount=st_finance_amount(st_finance_input($input,'amount',20));$title=st_finance_input($input,'title',180);$reference=st_finance_input($input,'reference',150);$source=st_finance_input($input,'source',30);if(!in_array($source,['sponsorship','grant','donation','other'],true))throw new InvalidArgumentException('Choose a manual income source.');
                $note=st_finance_input($input,'note',500);$duplicate=st_finance_sum($db,"SELECT COUNT(*) FROM st_finance_ledger WHERE environment=? AND kind='MANUAL_INCOME' AND reference=?",[$environment,$reference]);if($duplicate)throw new RuntimeException('This receipt reference is already recorded.');
                $result=st_finance_journal($db,$u,$eventId,$environment,'MANUAL_INCOME',$amount,$title,$reference);$details=['ledger_id'=>$result,'source'=>$source,'amount'=>$amount,'note'=>$note];break;
            case 'income_reverse':
                $id=st_finance_id($input);$rows=st_finance_query($db,'SELECT * FROM st_finance_ledger WHERE id=?',[$id]);$original=$rows[0]??null;
                if(!$original||$original['kind']!=='MANUAL_INCOME'||$original['environment']!==$environment)throw new RuntimeException('This income entry cannot be reversed.');$eventId=(int)$original['event_id'];st_finance_event($u,$eventId);st_finance_open($db,$eventId,$environment);
                if(st_finance_sum($db,'SELECT COUNT(*) FROM st_finance_ledger WHERE reverses_id=?',[$id]))throw new RuntimeException('This receipt was already reversed.');
                $reference=st_finance_input($input,'reference',150);$note=st_finance_input($input,'note',500);$result=st_finance_journal($db,$u,$eventId,$environment,'INCOME_REVERSAL',-(int)$original['amount'],$original['title'],$reference,null,$id);$details=['ledger_id'=>$result,'reverses_id'=>$id,'note'=>$note];break;
            case 'settlement_record':
                $provider=st_finance_input($input,'provider',20);if(!in_array($provider,['phonepe','razorpay'],true))throw new InvalidArgumentException('Choose a supported gateway.');
                $reference=st_finance_input($input,'reference',150);$bankReference=st_finance_input($input,'bank_reference',150);$bankDate=st_finance_date(st_finance_input($input,'bank_date',10));
                $fees=st_finance_amount(st_finance_input($input,'fees',20),true);$net=st_finance_amount(st_finance_input($input,'net',20),true);
                $list=st_finance_input($input,'order_ids',5000);if(!preg_match('/^[1-9][0-9]*(?:[\s,]+[1-9][0-9]*)*$/D',$list))throw new InvalidArgumentException('Enter numeric order IDs separated by commas.');$ids=array_values(array_unique(array_map('intval',preg_split('/[\s,]+/',$list))));if(count($ids)>200)throw new InvalidArgumentException('Record at most 200 orders in each settlement batch.');
                $gross=0;$refunds=0;$orders=[];
                foreach($ids as $id){$rows=st_finance_query($db,'SELECT * FROM az_orders WHERE id=?',[$id]);$order=$rows[0]??null;if(!$order||$order['environment']!==$environment||($order['provider']??'razorpay')!==$provider||!in_array($order['state'],['PAID','PAID_REVIEW','REFUNDED'],true)||empty($order['gateway_payment']))throw new RuntimeException('Every linked order must be a verified capture in this gateway and accounting environment.');
                    st_finance_event($u,(int)$order['event_id']);if(st_finance_sum($db,'SELECT COUNT(*) FROM st_settlement_orders WHERE order_id=?',[$id]))throw new RuntimeException('An order in this batch is already linked to a settlement.');
                    $r=st_finance_sum($db,'SELECT COALESCE(SUM(amount),0) FROM az_refunds WHERE order_id=?',[$id]);if($r>(int)$order['amount'])throw new RuntimeException('Refund totals exceed a capture. Resolve this discrepancy before settlement.');$gross+=(int)$order['amount'];$refunds+=$r;$orders[]=[$id,(int)$order['amount'],$r];
                }
                if($gross-$refunds-$fees!==$net)throw new RuntimeException('Bank net must equal linked verified captures minus actual refunds and gateway fees.');
                $db->prepare('INSERT INTO st_settlements(environment,provider,reference,gross,refunds,fees,net,bank_date,bank_reference,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)')->execute([$environment,$provider,$reference,$gross,$refunds,$fees,$net,$bankDate,$bankReference,$u['id'],$now]);$result=(int)$db->lastInsertId();
                $feeAllocation=st_finance_allocate_fees($fees,array_map(fn($r)=>['order_id'=>$r[0],'gross'=>$r[1]],$orders));
                foreach($orders as $order)$db->prepare('INSERT INTO st_settlement_orders(settlement_id,order_id,gross,refunds,fees) VALUES(?,?,?,?,?)')->execute([$result,...$order,$feeAllocation[$order[0]]]);$details=['settlement_id'=>$result,'orders'=>$ids,'gross'=>$gross,'refunds'=>$refunds,'fees'=>$fees,'net'=>$net,'bank_reference'=>$bankReference,'fee_allocation'=>$feeAllocation];break;
            case 'reconcile':
                $date=st_finance_date(st_finance_input($input,'statement_date',10));$bank=st_finance_amount(st_finance_input($input,'bank_total',20),true);$reference=st_finance_input($input,'reference',150);$note=st_finance_input($input,'note',1000);
                $recorded=st_finance_sum($db,'SELECT COALESCE(SUM(net),0) FROM st_settlements WHERE environment=? AND bank_date<=?',[$environment,$date]);$difference=$bank-$recorded;
                $db->prepare('INSERT INTO st_reconciliations(environment,statement_date,bank_total,recorded_total,difference,reference,note,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)')->execute([$environment,$date,$bank,$recorded,$difference,$reference,$note,$u['id'],$now]);$result=(int)$db->lastInsertId();$details=['reconciliation_id'=>$result,'bank'=>$bank,'recorded'=>$recorded,'difference'=>$difference,'reference'=>$reference];break;
            case 'close':
                if(st_finance_sum($db,"SELECT COUNT(*) FROM az_orders WHERE event_id=? AND environment=? AND provider='manual' AND (state IN ('PENDING_REVIEW','PAID_REVIEW') OR (state='AWAITING_PROOF' AND expires_at>?))",[$eventId,$environment,time()]))throw new RuntimeException('Resolve payment reviews, active reservations and ticket capacity before closing.');
                if(st_finance_sum($db,"SELECT COUNT(*) FROM st_expenses WHERE event_id=? AND environment=? AND status IN ('DRAFT','SUBMITTED','APPROVED')",[$eventId,$environment]))throw new RuntimeException('Resolve all drafts, submissions and approved unpaid expenses before closing.');
                $note=st_finance_input($input,'note',1000);$snapshot=st_finance_snapshot($db,$eventId,$environment);$json=json_encode($snapshot,JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE);$snapshotHash=hash('sha256',$json);
                $budget=st_finance_budget($db,$eventId,$environment);if(!$budget['revision'])$db->prepare('INSERT INTO st_budgets(event_id,environment,allocated,closed,updated_by,updated_at) VALUES(?,?,0,1,?,?)')->execute([$eventId,$environment,$u['id'],$now]);else $db->prepare('UPDATE st_budgets SET closed=1,revision=revision+1,updated_by=?,updated_at=? WHERE event_id=? AND environment=?')->execute([$u['id'],$now,$eventId,$environment]);
                $db->prepare('INSERT INTO st_closeouts(event_id,environment,snapshot,snapshot_hash,note,created_by,created_at) VALUES(?,?,?,?,?,?,?)')->execute([$eventId,$environment,$json,$snapshotHash,$note,$u['id'],$now]);$result=(int)$db->lastInsertId();$details=['closeout_id'=>$result,'snapshot_hash'=>$snapshotHash,'note'=>$note];break;
            case 'reopen':
                if(!(int)st_finance_budget($db,$eventId,$environment)['closed'])throw new RuntimeException('This event is already open.');$note=st_finance_input($input,'note',1000);$db->prepare('UPDATE st_budgets SET closed=0,revision=revision+1,updated_by=?,updated_at=? WHERE event_id=? AND environment=?')->execute([$u['id'],$now,$eventId,$environment]);$result=$eventId;$details=['note'=>$note];break;
        }
        st_finance_audit($db,$u,$action,$eventId,$environment,$details);
        $db->prepare('INSERT INTO st_finance_commands(request_key,user_id,action,input_hash,result_id,created_at) VALUES(?,?,?,?,?,?)')->execute([$key,$u['id'],$action,$hash,$result,$now]);$db->commit();return $result;
    }catch(Throwable $e){if($db->inTransaction())$db->rollBack();if($newEvidencePath&&is_file($newEvidencePath))unlink($newEvidencePath);throw $e;}
}

function st_finance_action(array $u,string $action): bool {
    if(!str_starts_with($action,'finance_'))return false;az_csrf();$input=$_POST;if($action==='finance_receipt_upload'){$file=$_FILES['receipt']??null;$input['evidence_file']=$file;$input['evidence_hash']=is_array($file)&&is_file($file['tmp_name']??'')?hash_file('sha256',$file['tmp_name']):'';}st_finance_mutate($u,substr($action,8),$input);cms_flash('Financial record saved.');return true;
}
function st_finance_summary(array $u,?int $eventId=null,string $environment='live'): array {
    st_finance_permission($u,'view');st_finance_environment($environment);$db=cms_db();$scope=st_finance_scope($u,$eventId,'o.event_id');$params=[$environment,...$scope['params']];
    $row=st_finance_query($db,"SELECT COALESCE(SUM(CASE WHEN o.state IN ('PAID','PAID_REVIEW','REFUNDED') AND (m.status='APPROVED' OR (o.provider<>'manual' AND o.gateway_payment IS NOT NULL AND o.gateway_payment<>'')) THEN o.amount ELSE 0 END),0) AS gross,COUNT(DISTINCT CASE WHEN o.state IN ('PAID','PAID_REVIEW','REFUNDED') AND (m.status='APPROVED' OR (o.provider<>'manual' AND o.gateway_payment IS NOT NULL AND o.gateway_payment<>'')) THEN o.participant_id END) AS paying_participants,COALESCE(SUM(CASE WHEN o.state='PAID' THEN o.quantity ELSE 0 END),0) AS paid_entries,COALESCE(SUM(CASE WHEN o.state IN ('AWAITING_PROOF','PENDING_REVIEW','CREATING','CREATED','PENDING') THEN 1 ELSE 0 END),0) AS pending_orders FROM az_orders o LEFT JOIN az_manual_payments m ON m.order_id=o.id WHERE o.environment=? AND ".$scope['sql'],$params)[0];
    $refunds=st_finance_sum($db,'SELECT COALESCE(SUM(r.amount),0) FROM az_refunds r JOIN az_orders o ON o.id=r.order_id WHERE o.environment=? AND '.$scope['sql'],$params);
    $scope=st_finance_scope($u,$eventId,'event_id');$params=[$environment,...$scope['params']];
    $manual=st_finance_sum($db,"SELECT COALESCE(SUM(amount),0) FROM st_finance_ledger WHERE environment=? AND kind IN ('MANUAL_INCOME','INCOME_REVERSAL') AND ".$scope['sql'],$params);
    $spend=-st_finance_sum($db,"SELECT COALESCE(SUM(amount),0) FROM st_finance_ledger WHERE environment=? AND kind IN ('EXPENSE_PAYMENT','EXPENSE_REVERSAL') AND ".$scope['sql'],$params);
    $approved=st_finance_sum($db,"SELECT COALESCE(SUM(amount),0) FROM st_expenses WHERE environment=? AND status='APPROVED' AND ".$scope['sql'],$params);
    $allocation=st_finance_sum($db,'SELECT COALESCE(SUM(allocated),0) FROM st_budgets WHERE environment=? AND '.$scope['sql'],$params);
    $submitted=st_finance_sum($db,"SELECT COUNT(*) FROM st_expenses WHERE environment=? AND status='SUBMITTED' AND ".$scope['sql'],$params);
    $orderScope=st_finance_scope($u,$eventId,'o.event_id');
    $settledGross=st_finance_sum($db,'SELECT COALESCE(SUM(so.gross),0) FROM st_settlement_orders so JOIN az_orders o ON o.id=so.order_id WHERE o.environment=? AND '.$orderScope['sql'],[$environment,...$orderScope['params']]);
    $gatewayFees=st_finance_sum($db,'SELECT COALESCE(SUM(so.fees),0) FROM st_settlement_orders so JOIN az_orders o ON o.id=so.order_id WHERE o.environment=? AND '.$orderScope['sql'],[$environment,...$orderScope['params']]);
    $settledNet=st_finance_sum($db,'SELECT COALESCE(SUM(so.gross-so.refunds-so.fees),0) FROM st_settlement_orders so JOIN az_orders o ON o.id=so.order_id WHERE o.environment=? AND '.$orderScope['sql'],[$environment,...$orderScope['params']]);
    $lateRefunds=st_finance_sum($db,'SELECT COALESCE(SUM(COALESCE(r.refunds,0)-so.refunds),0) FROM st_settlement_orders so JOIN az_orders o ON o.id=so.order_id LEFT JOIN (SELECT order_id,SUM(amount) AS refunds FROM az_refunds GROUP BY order_id) r ON r.order_id=o.id WHERE o.environment=? AND '.$orderScope['sql'],[$environment,...$orderScope['params']]);
    $tickets=st_finance_sum($db,"SELECT COUNT(*) FROM az_tickets t JOIN az_orders o ON o.id=t.order_id WHERE o.environment=? AND t.status='VALID' AND ".$orderScope['sql'],[$environment,...$orderScope['params']]);
    $checkins=st_finance_sum($db,'SELECT COUNT(*) FROM az_checkins c JOIN az_tickets t ON t.id=c.ticket_id JOIN az_orders o ON o.id=t.order_id WHERE o.environment=? AND '.$orderScope['sql'],[$environment,...$orderScope['params']]);
    $directGross=st_finance_sum($db,"SELECT COALESCE(SUM(o.amount),0) FROM az_orders o JOIN az_manual_payments m ON m.order_id=o.id WHERE o.environment=? AND m.status='APPROVED' AND ".$orderScope['sql'],[$environment,...$orderScope['params']]);
    return array_map('intval',$row)+['direct_receipts'=>$directGross]+['refunds'=>$refunds,'net_registration'=>(int)$row['gross']-$refunds,'manual_income'=>$manual,'paid_expenses'=>$spend,'approved_commitments'=>$approved,'allocated'=>$allocation,'available_budget'=>$allocation-$spend-$approved,'net_position'=>(int)$row['gross']-$refunds+$manual-$spend-$gatewayFees,'gateway_fees'=>$gatewayFees,'settled_net'=>$settledNet,'submitted_expenses'=>$submitted,'settled_gross'=>$settledGross,'unsettled_gross'=>(int)$row['gross']-$directGross-$settledGross,'post_settlement_refunds'=>$lateRefunds,'valid_tickets'=>$tickets,'checkins'=>$checkins];
}
function st_finance_rows(array $u,string $kind,?int $eventId=null,string $environment='live',int $limit=100,int $offset=0): array {
    st_finance_permission($u,'view');st_finance_environment($environment);$limit=max(1,min(500,$limit));$offset=max(0,$offset);$db=cms_db();
    $tables=['budgets'=>'st_budgets','expenses'=>'st_expenses','ledger'=>'st_finance_ledger','closeouts'=>'st_closeouts','audit'=>'st_finance_audit','evidence'=>'st_finance_evidence'];
    if(isset($tables[$kind])){$scope=st_finance_scope($u,$eventId,'f.event_id');return st_finance_query($db,'SELECT f.*,c.title AS event_title FROM '.$tables[$kind].' f LEFT JOIN cms_content c ON c.id=f.event_id WHERE f.environment=? AND '.$scope['sql'].' ORDER BY '.($kind==='budgets'?'f.event_id':'f.id DESC').' LIMIT '.$limit.' OFFSET '.$offset,[$environment,...$scope['params']]);}
    if($kind==='settlements'||$kind==='reconciliations'){st_finance_permission($u,'view',true);return st_finance_query($db,'SELECT * FROM st_'.$kind.' WHERE environment=? ORDER BY id DESC LIMIT '.$limit.' OFFSET '.$offset,[$environment]);}
    throw new InvalidArgumentException('Unknown financial report.');
}
function st_finance_expense_record(array $u,int $id,?int $eventId=null,string $environment='live'): ?array {
    st_finance_permission($u,'view');st_finance_environment($environment);$scope=st_finance_scope($u,$eventId,'f.event_id');
    $rows=st_finance_query(cms_db(),'SELECT f.*,c.title AS event_title FROM st_expenses f JOIN cms_content c ON c.id=f.event_id WHERE f.id=? AND f.environment=? AND '.$scope['sql'],[$id,$environment,...$scope['params']]);return $rows[0]??null;
}
function st_finance_expense_queue(array $u,?int $eventId=null,string $environment='live',int $limit=8): array {
    st_finance_permission($u,'view');st_finance_environment($environment);$scope=st_finance_scope($u,$eventId,'f.event_id');$limit=max(1,min(100,$limit));
    return st_finance_query(cms_db(),"SELECT f.*,c.title AS event_title FROM st_expenses f JOIN cms_content c ON c.id=f.event_id WHERE f.environment=? AND f.status IN ('SUBMITTED','APPROVED') AND ".$scope['sql'].' ORDER BY f.id ASC LIMIT '.$limit,[$environment,...$scope['params']]);
}

/** Stable closeout fingerprint: raw IDs and amounts catch a late refund/capture
 * even if offsetting changes leave the headline totals unchanged. */
function st_finance_snapshot(PDO $db,int $eventId,string $environment): array {
    $budget=st_finance_budget($db,$eventId,$environment);
    $event=cms_record($eventId);
    $setup=['id'=>$eventId,'slug'=>$event['slug']??'','title'=>$event['title']??'','registration_form'=>az_registration_fields($event['fields']??[]),'payment_methods'=>az_payment_methods($event['fields']??[],false),'ticket_types'=>json_decode($event['fields']['ticket_types']??'[]',true)?:[]];
    $orders=st_finance_query($db,'SELECT id,public_id,participant_id,event_slug,ticket_type,amount,quantity,state,provider,gateway_payment,snapshot,answers,created_at,updated_at FROM az_orders WHERE event_id=? AND environment=? ORDER BY id',[$eventId,$environment]);
    $refunds=st_finance_query($db,'SELECT r.refund_id,r.order_id,r.amount FROM az_refunds r JOIN az_orders o ON o.id=r.order_id WHERE o.event_id=? AND o.environment=? ORDER BY r.refund_id',[$eventId,$environment]);
    $ledger=st_finance_query($db,'SELECT id,kind,amount,reference,source_id,reverses_id FROM st_finance_ledger WHERE event_id=? AND environment=? ORDER BY id',[$eventId,$environment]);
    $expenses=st_finance_query($db,'SELECT id,title,category,payee,amount,status,invoice_reference,payment_reference,created_by,reviewed_by,paid_by FROM st_expenses WHERE event_id=? AND environment=? ORDER BY id',[$eventId,$environment]);
    $settlements=st_finance_query($db,'SELECT so.order_id,so.gross,so.refunds,so.fees,(so.gross-so.refunds-so.fees) AS event_bank_net,s.id,s.reference,s.bank_reference,s.bank_date FROM st_settlement_orders so JOIN st_settlements s ON s.id=so.settlement_id JOIN az_orders o ON o.id=so.order_id WHERE o.event_id=? AND o.environment=? ORDER BY so.order_id',[$eventId,$environment]);
    $payments=st_finance_query($db,'SELECT m.* FROM az_manual_payments m JOIN az_orders o ON o.id=m.order_id WHERE o.event_id=? AND o.environment=? ORDER BY m.order_id',[$eventId,$environment]);
    $proofs=st_finance_query($db,'SELECT p.id,p.order_id,p.mime,p.size_bytes,p.sha256,p.reference,p.paid_on,p.uploaded_at FROM az_payment_proofs p JOIN az_orders o ON o.id=p.order_id WHERE o.event_id=? AND o.environment=? ORDER BY p.id',[$eventId,$environment]);
    $reviews=st_finance_query($db,'SELECT r.* FROM az_payment_reviews r JOIN az_orders o ON o.id=r.order_id WHERE o.event_id=? AND o.environment=? ORDER BY r.id',[$eventId,$environment]);
    $tickets=st_finance_query($db,'SELECT t.id,t.ticket_id,t.order_id,t.status,t.checked_at,t.checked_by,b.previous_status,b.reason,b.blocked_by,b.blocked_at,b.unblocked_by,b.unblocked_at FROM az_tickets t JOIN az_orders o ON o.id=t.order_id LEFT JOIN az_ticket_blocks b ON b.ticket_id=t.id WHERE o.event_id=? AND o.environment=? ORDER BY t.id',[$eventId,$environment]);
    $comparisons=$environment==='live'?st_finance_query($db,'SELECT * FROM az_event_reconciliations WHERE event_id=? ORDER BY id',[$eventId]):[];
    return ['schema'=>3,'event_setup'=>$setup,'payments'=>$payments,'payment_proofs'=>$proofs,'payment_reviews'=>$reviews,'tickets'=>$tickets,'account_comparisons'=>$comparisons,'event_id'=>$eventId,'environment'=>$environment,'allocated'=>(int)$budget['allocated'],'orders'=>$orders,'refunds'=>$refunds,'ledger'=>$ledger,'expenses'=>$expenses,'settlements'=>$settlements];
}
function st_finance_closeout_changed(array $u,array $closeout): bool {
    st_finance_permission($u,'view');$eventId=(int)$closeout['event_id'];st_finance_event($u,$eventId);$environment=st_finance_environment($closeout['environment']);
    return !hash_equals($closeout['snapshot_hash'],hash('sha256',json_encode(st_finance_snapshot(cms_db(),$eventId,$environment),JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE)));
}
function st_finance_csv_cell(mixed $value): string {
    if(is_int($value))return (string)$value;$value=(string)($value??'');return preg_match('/^[\s\x00-\x1f]*[=+@-]/u',$value)?"'".$value:$value;
}
function st_finance_export(array $u,string $export,?int $eventId,string $environment): void {
    st_finance_permission($u,'export');st_finance_permission($u,'view');st_finance_environment($environment);$scope=st_finance_scope($u,$eventId,'event_id');
    if(!in_array($export,['summary','expenses','ledger','budgets','closeouts','audit','settlements','reconciliations','archive'],true))throw new InvalidArgumentException('Choose a financial export.');
    if($export==='archive'){
        if($eventId===null)throw new InvalidArgumentException('Select an event for its complete archive.');$data=st_finance_snapshot(cms_db(),$eventId,$environment);$data['closeouts']=st_finance_query(cms_db(),'SELECT * FROM st_closeouts WHERE event_id=? AND environment=? ORDER BY id',[$eventId,$environment]);$data['event_activity']=st_finance_query(cms_db(),'SELECT * FROM st_event_activity WHERE event_id=? ORDER BY id',[$eventId]);$data['audit']=st_finance_query(cms_db(),'SELECT * FROM st_finance_audit WHERE event_id=? AND environment=? ORDER BY id',[$eventId,$environment]);$data['evidence']=st_finance_query(cms_db(),'SELECT id,title,mime,size_bytes,sha256,uploaded_by,created_at FROM st_finance_evidence WHERE event_id=? AND environment=? ORDER BY id',[$eventId,$environment]);$body=json_encode($data,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);$type='application/json';$extension='json';
    }else{
        $stream=fopen('php://temp','w+');if($export==='summary')$rows=[st_finance_summary($u,$eventId,$environment)];else{
            // Export every row, not the paginated display. Scope and permissions
            // are rechecked before preparing the unbounded, streaming query.
            $tables=['expenses'=>'st_expenses','ledger'=>'st_finance_ledger','budgets'=>'st_budgets','closeouts'=>'st_closeouts','audit'=>'st_finance_audit','settlements'=>'st_settlements','reconciliations'=>'st_reconciliations'];
            if(in_array($export,['settlements','reconciliations'],true)){st_finance_permission($u,'view',true);$scope=['sql'=>'1=1','params'=>[]];}
            $s=cms_db()->prepare('SELECT * FROM '.$tables[$export].' WHERE environment=? AND '.$scope['sql'].' ORDER BY '.($export==='budgets'?'event_id':'id'));$s->execute([$environment,...$scope['params']]);$rows=$s;
        }
        $header=false;foreach($rows as $row){if(!$header){fputcsv($stream,array_keys($row),',','"','');$header=true;}fputcsv($stream,array_map('st_finance_csv_cell',array_values($row)),',','"','');}if(!$header)fputcsv($stream,['No records in this scope'],',','"','');rewind($stream);$body=stream_get_contents($stream);fclose($stream);$type='text/csv';$extension='csv';
    }
    st_finance_audit(cms_db(),$u,'export',$eventId,$environment,['report'=>$export,'bytes'=>strlen($body)]);
    header('Content-Type: '.$type.'; charset=UTF-8');header('Content-Disposition: attachment; filename="anazori-'.$environment.'-'.($eventId??'festival').'-'.$export.'-'.gmdate('Ymd').'.'.$extension.'"');header('Cache-Control: private, no-store');header('X-Content-Type-Options: nosniff');echo $body;exit;
}
