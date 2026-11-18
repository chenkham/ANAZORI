<?php
declare(strict_types=1);

function az_install_manual_finance(PDO $db): void {
    if($db->query("SELECT value FROM cms_settings WHERE setting_key='manual_finance_schema'")->fetchColumn()==='1')return;
    $id=$db->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite'?'INTEGER PRIMARY KEY AUTOINCREMENT':'INT AUTO_INCREMENT PRIMARY KEY';
    $db->exec("CREATE TABLE IF NOT EXISTS az_event_reconciliations (
        id $id,event_id INT NOT NULL,statement_date VARCHAR(10) NOT NULL,bank_total BIGINT NOT NULL,
        recorded_total BIGINT NOT NULL,difference BIGINT NOT NULL,reference VARCHAR(150) NOT NULL,note TEXT NOT NULL,
        created_by INT NOT NULL,created_at VARCHAR(40) NOT NULL
    )");
    az_schema_marker($db,'manual_finance_schema');
}

/** A recorded refund documents money already returned; it never sends a payment. */
function az_record_manual_refund(array $actor,int $orderId,array $input): void {
    $amount=st_finance_amount(az_setup_text($input,'amount',20));$reference=az_setup_text($input,'reference',100);$note=az_setup_text($input,'note',1000);
    if(!preg_match('/^[A-Za-z0-9][A-Za-z0-9 -]{5,99}$/D',$reference)||mb_strlen($note)<3||($input['refund_confirmed']??'')!=='yes')throw new InvalidArgumentException('Confirm the completed refund and enter its reference and reason.');
    $db=cms_db();$db->beginTransaction();
    try{
        az_lock($db);$actor=st_refresh_user($actor);$order=az_payment_actor_order($actor,$orderId);$payment=az_manual_payment($orderId);
        if($order['provider']!=='manual'||!$payment||$payment['status']!=='APPROVED'||!in_array($order['state'],['PAID','PAID_REVIEW','REFUNDED'],true))throw new RuntimeException('Only a confirmed event payment can have a recorded refund.');
        st_finance_open($db,(int)$order['event_id'],'live');
        $key='manual:'.az_reference_key(json_decode($payment['method_snapshot'],true),$reference);
        $query=$db->prepare('SELECT * FROM az_refunds WHERE refund_id=?');$query->execute([$key]);$old=$query->fetch();
        if($old){if((int)$old['order_id']!==$orderId||(int)$old['amount']!==$amount)throw new RuntimeException('This refund reference is already used.');$db->commit();return;}
        $query=$db->prepare('SELECT COALESCE(SUM(amount),0) FROM az_refunds WHERE order_id=?');$query->execute([$orderId]);$refunded=(int)$query->fetchColumn();
        if($refunded+$amount>(int)$order['amount'])throw new RuntimeException('The refund cannot exceed the amount still held.');
        $now=gmdate('c');$db->prepare('INSERT INTO az_refunds(refund_id,order_id,amount,received_at) VALUES(?,?,?,?)')->execute([$key,$orderId,$amount,$now]);
        if($refunded+$amount===(int)$order['amount']){
            $db->prepare("UPDATE az_orders SET state='REFUNDED',updated_at=? WHERE id=?")->execute([$now,$orderId]);
            $db->prepare("UPDATE az_tickets SET status='VOID' WHERE order_id=?")->execute([$orderId]);
        }
        $db->prepare('INSERT INTO az_payment_reviews(order_id,staff_id,action,proof_id,note,created_at) VALUES(?,?,?,?,?,?)')->execute([$orderId,$actor['id'],'refund',$payment['proof_id'],$reference.' · '.az_money($amount).' · '.$note,$now]);
        st_event_audit($actor,(int)$order['event_id'],'payment.refund',$order['public_id'].' · '.$reference.' · '.az_money($amount));
        st_finance_audit($db,$actor,'payment_refund',(int)$order['event_id'],'live',['order'=>$order['public_id'],'reference'=>$reference,'amount'=>$amount,'note'=>$note]);
        az_notify_order89(az_order($orderId),'refund',$key,['refund_amount'=>az_money($amount)]);
        $db->commit();
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
}

function az_reconcile_event_receipts(array $actor,int $eventId,array $input): void {
    $date=az_calendar_date(az_setup_text($input,'statement_date',10));$amount=st_finance_amount(az_setup_text($input,'bank_total',20),true);
    $reference=az_setup_text($input,'reference',150);$note=az_setup_text($input,'note',1000);
    if(!$date||$date>new DateTimeImmutable('today',new DateTimeZone('Asia/Kolkata'))||$reference===''||$note==='')throw new InvalidArgumentException('Enter the statement date, reference and comparison note.');
    $db=cms_db();$db->beginTransaction();
    try{
        az_lock($db);$actor=st_refresh_user($actor);st_require_event($actor,$eventId);
        if($actor['must_change_password']||!cms_can($actor,'finance','view')||!cms_can($actor,'payments','verify'))throw new RuntimeException('No event reconciliation access.');
        st_finance_open($db,$eventId,'live');
        $query=$db->prepare("SELECT COALESCE(SUM(o.amount),0) FROM az_orders o JOIN az_manual_payments m ON m.order_id=o.id WHERE o.event_id=? AND m.status='APPROVED' AND m.paid_on<=?");$query->execute([$eventId,$date->format('Y-m-d')]);$gross=(int)$query->fetchColumn();
        $through=$date->modify('+1 day')->setTimezone(new DateTimeZone('UTC'))->format('c');
        $query=$db->prepare("SELECT COALESCE(SUM(r.amount),0) FROM az_refunds r JOIN az_orders o ON o.id=r.order_id WHERE o.event_id=? AND o.provider='manual' AND r.received_at<?");$query->execute([$eventId,$through]);$net=$gross-(int)$query->fetchColumn();
        $db->prepare('INSERT INTO az_event_reconciliations(event_id,statement_date,bank_total,recorded_total,difference,reference,note,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)')->execute([$eventId,$date->format('Y-m-d'),$amount,$net,$amount-$net,$reference,$note,$actor['id'],gmdate('c')]);
        st_finance_audit($db,$actor,'event_receipts_reconcile',$eventId,'live',['bank_total'=>$amount,'recorded_total'=>$net,'difference'=>$amount-$net,'reference'=>$reference]);
        $db->commit();
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
}

function az_event_receipts_view(array $actor,array $events,?int $eventId): void {
    echo '<details class="studio-disclosure"><summary>Event account reconciliation</summary><div class="disclosure-content"><p class="help">Compare this event’s registration credits minus refunds with the same entries in the receiving accounts. Exclude unrelated personal transactions and expenses.</p>';
    if($eventId){
        $query=cms_db()->prepare('SELECT * FROM az_event_reconciliations WHERE event_id=? ORDER BY id DESC LIMIT 10');$query->execute([$eventId]);
        foreach($query as $row)echo '<div class="review-row"><span>'.e($row['statement_date'].' · '.$row['reference']).'<small>'.e($row['note']).'</small></span><strong>Difference '.e(az_money((int)$row['difference'])).'</strong></div>';
    }
    if(cms_can($actor,'payments','verify')){
        echo '<form method="post" class="form-grid">';cms_hidden('reconcile_event_receipts');
        echo '<label class="field"><span>Event</span><select name="event_id" required>';
        foreach($events as $event)if(!$eventId||(int)$event['id']===$eventId)echo '<option value="'.(int)$event['id'].'">'.e($event['title']).'</option>';
        echo '</select></label><label class="field"><span>Statement through date</span><input type="date" name="statement_date" required></label><label class="field"><span>Event credits minus refunds (₹)</span><input type="number" name="bank_total" min="0" step="0.01" required></label><label class="field"><span>Statement reference</span><input name="reference" maxlength="150" required></label><label class="field wide"><span>Comparison note</span><textarea name="note" maxlength="1000" required></textarea></label><div class="form-actions"><button class="quiet-button" type="submit">Save comparison</button></div></form>';
    }
    echo '</div></details>';
}
