<?php
declare(strict_types=1);

/** One receiver configuration can cover every paid category in this game form. */
function az_payment_targets108(array $field,array $tickets): array {
    if(!empty($field['payment_ticket']))return [$field['payment_ticket']];
    return !empty($field['payment_dynamic'])?array_column(array_filter($tickets,fn($ticket)=>(int)$ticket['price']>0),'id'):[];
}

function az_payment_uri108(string $upi,string $name,int $amount,string $reference): string {
    if(!preg_match('/^[a-zA-Z0-9._-]{2,80}@[a-zA-Z0-9.-]{2,30}$/D',$upi)||$amount<100||!preg_match('/^ORDER-[A-F0-9]{16}$/D',$reference))throw new InvalidArgumentException('Invalid payment details.');
    $name=trim($name)?:'Anazori';
    if(mb_strlen($name)>80||preg_match('/[\x00-\x1F\x7F]/',$name))throw new InvalidArgumentException('Check the receiving account name.');
    return 'upi://pay?'.http_build_query(['pa'=>$upi,'pn'=>$name,'am'=>number_format($amount/100,2,'.',''),'cu'=>'INR','tr'=>$reference,'tn'=>'Form '.$reference],'','&',PHP_QUERY_RFC3986);
}

/** Reserve the eventual order ID in the existing server-owned draft, before payment. */
function az_payment_reference108(array $person,array $event,array $fields,string $game=''): string {
    $db=cms_db();$db->beginTransaction();
    try{
        az_lock($db);$context=az_draft_context81($game);$draft=az_checkout_draft((int)$person['id'],(int)$event['id'],$context);
        $state=json_decode($draft['state_json']??'{}',true)?:[];$reference=$state['payment_reference']??'';
        if(!is_string($reference)||!preg_match('/^ORDER-[A-F0-9]{16}$/D',$reference)){
            $reference='ORDER-'.strtoupper(bin2hex(random_bytes(8)));$state['payment_reference']=$reference;
            if($draft)$db->prepare('UPDATE az_checkout_drafts SET state_json=? WHERE participant_id=? AND event_id=? AND context_id=?')->execute([json_encode($state),$person['id'],$event['id'],$context]);
            else $db->prepare('INSERT INTO az_checkout_drafts(participant_id,event_id,context_id,answers_json,game_id,schema_hash,state_json,revision,updated_at) VALUES(?,?,?,?,?,?,?,0,?)')->execute([$person['id'],$event['id'],$context,'{}',$game,az_draft_schema_hash($fields),json_encode($state),gmdate('c')]);
        }
        $db->commit();return $reference;
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
}

function az_payment_qr_url108(string $slug,string $ticket,string $game='',string $order=''): string {
    return '/payment-qr.php?'.http_build_query(array_filter(['event'=>$slug,'type'=>$ticket,'game'=>$game,'order'=>$order],fn($value)=>$value!==''),'','&',PHP_QUERY_RFC3986);
}

/** Prices remain ticket prices; publishing never changes an existing order snapshot. */
function az_form_prices108(array $fields,mixed $prices,string $game=''): array {
    if(!is_array($prices)||count($prices)>50)throw new InvalidArgumentException('Check the ticket prices.');
    $allowed=array_column(az_ticket_options81($fields,$game),'id');$rows=az_prices($fields);
    foreach($prices as $id=>$value){if(!in_array($id,$allowed,true)||!is_string($value))throw new InvalidArgumentException('Choose a ticket in this form before editing its price.');$amount=az_inr_to_paise(trim($value));foreach($rows as &$row)if($row['id']===$id)$row['price']=$amount;unset($row);}
    $fields['ticket_types']=json_encode($rows,JSON_THROW_ON_ERROR);return $fields;
}

function st_form_prices108(array $tickets): void {
    if(!$tickets)return;
    echo '<details class="studio-disclosure"><summary>Ticket prices for this form</summary><div class="disclosure-content form-grid"><p class="help wide">Edit the fixed total for each ticket. For ₹150 per person, use ₹150, ₹300, ₹450 and ₹600 for one to four people. Publish to apply. Existing submitted registrations keep their original price.</p>';
    foreach($tickets as $ticket)echo '<label class="field"><span>'.e($ticket['label']).' · total (₹)</span><input type="number" min="0" max="999999.99" step="0.01" data-ticket-price108="'.e($ticket['id']).'" value="'.number_format((int)$ticket['price']/100,2,'.','').'"></label>';
    echo '</div></details>';
}
