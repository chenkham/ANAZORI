<?php
declare(strict_types=1);

function az_form_score(array $schema,array $answers): array {
    $score=0;$maximum=0;
    foreach($schema as $field){
        $points=(int)($field['points']??0);$key=$field['answer_key']??[];
        if(!$points||!$key||!array_key_exists($field['label'],$answers))continue;
        $maximum+=$points;$given=explode("\n",mb_strtolower(trim($answers[$field['label']])));$expected=array_map(fn($v)=>mb_strtolower(trim($v)),$key);
        sort($given);sort($expected);if($given===$expected)$score+=$points;
    }
    return [$score,$maximum];
}
function az_create_form_order(array $participant,string $slug,string $typeId,int $quantity,array $answers,array $files,string $gameId='',int $editId=0,int $revision=0,string $teamName=''): array {
    if(!$participant['email_verified']||empty($participant['profile_completed']))throw new RuntimeException('Complete your profile and verify your email before registering.');
    if($quantity!==1)throw new InvalidArgumentException('Each registration has exactly one ticket.');
    az_limit('form-submit',(string)$participant['id'],20,900);$written=[];$db=cms_db();$db->beginTransaction();
    try{
        az_lock($db);$q=$db->prepare('SELECT * FROM az_participants WHERE id=? AND active=1 AND email_verified=1');$q->execute([$participant['id']]);$current=$q->fetch();
        if(!$current||(int)$current['session_version']!==(int)$participant['session_version'])throw new RuntimeException('Your account changed. Sign in again.');
        $event=az_event($slug);if(!$event||az_participation_mode($event)!=='registration')throw new RuntimeException('This event takes contributions, without ticket registration.');
        $fields=$event['fields'];if(!$editId){az_selected_game($fields,$gameId);az_require_internal_registration97($fields,$gameId);$fields=az_game_fields81($fields,$gameId);}$settings=az_form_settings($fields);$existing=[];$order=null;
        if(az_participation_mode($event)==='performers'&&($quantity!==1||$typeId!=='performer-pass'||$gameId!==''))throw new InvalidArgumentException('Submit one free performer application from your own account.');
        if($editId){
            $order=az_order($editId);$response=az_form_response($editId);
            if(!$order||!$response||(int)$order['participant_id']!==(int)$current['id']||(int)$order['event_id']!==(int)$event['id']||$order['provider']!=='form')throw new RuntimeException('Response unavailable.');
            $settings=json_decode($response['settings_json'],true);
            if(!in_array($order['state'],['FORM_PENDING','FORM_CORRECTION'],true)||($order['state']!=='FORM_CORRECTION'&&empty($settings['allow_edit'])))throw new RuntimeException('This response is locked for review.');
            if($revision!==(int)$response['revision'])throw new RuntimeException('This response changed. Reload before submitting.');
            $fields['registration_form']=$response['schema_json'];$existing=az_registration_files($editId);
            $quantity=(int)$order['quantity'];$typeId=$order['ticket_type'];$snapshot=json_decode($order['snapshot'],true);$gameId=$snapshot['game_id']??'';
        }else{
            if(cms_event_phase($fields)!=='open'||empty($settings['accepting']))throw new RuntimeException('This registration form is closed.');
            if($saved=az_existing_event_order((int)$current['id'],(int)$event['id'],$gameId))throw new RuntimeException(az_duplicate_registration_message($saved));
        }
        $type=$order?null:az_registration_entry($fields,$gameId,$typeId);if(!$order&&$type)$typeId=$type['id'];
        if(!$type&&!$order)throw new RuntimeException('Choose an available pass.');
        $fields['_ticket_id']=$typeId;$fields['_ticket_price']=$order?(int)$order['amount']:(int)$type['price'];
        $linkedQrs=az_ticket_qrs85($fields);
        if(!$order&&$fields['_ticket_price']>0&&$linkedQrs&&!isset($linkedQrs[$typeId]))throw new RuntimeException('Payment QR setup for this ticket is not ready. Contact the event coordinator before paying.');
        $game=$order?['id'=>$gameId,'label'=>$snapshot['game']??'']:az_selected_game($fields,$gameId);
        if(!$order&&!empty($type['game'])&&$type['game']!==($game['id']??''))throw new RuntimeException('Choose a pass for your game.');
        if(!$order&&$type['capacity']>0&&az_reserved((int)$event['id'],$typeId,'live')+$quantity>$type['capacity'])throw new RuntimeException('This pass is at capacity.');
        $kind=$order?($snapshot['registration_kind']??'individual'):'single';
        if($kind==='team'){
            if($order)$teamName=$snapshot['team_name']??$teamName;
            if(mb_strlen(trim($teamName))<2||mb_strlen($teamName)>120||preg_match('/[\x00-\x1F]/',$teamName))throw new InvalidArgumentException('Enter your team name.');
        }else $teamName='';
        $validated=az_registration_answers($fields,$answers,'registration',$gameId);
        $draftFiles=az_checkout_draft_files((int)$current['id'],(int)$event['id'],az_draft_context81($gameId,$editId));
        if($draftFiles){$replaced=array_column($draftFiles,'field_id');$existing=[...array_filter($existing,fn($file)=>!in_array($file['field_id'],$replaced,true)),...$draftFiles];}
        $groups=az_collect_form_uploads($fields,$answers,$files,'registration',$gameId,$existing);$now=gmdate('c');
        $draftContext=az_draft_context81($gameId,$editId);
        if(!$order){
            $snapshot=['title'=>$event['title'],'type'=>$type['label'],'game_id'=>$game['id']??'','game'=>$game['label']??'','starts_at'=>$fields['starts_at'],'ends_at'=>$fields['ends_at'],'venue'=>$fields['venue']?:setting('venue'),'rules_pdf'=>$fields['rules_pdf'],'name'=>$current['name'],'email'=>$current['email'],'registration_form'=>az_public_registration_schema($fields),'form_workflow'=>true];
            $snapshot['registration_kind']=$kind;$snapshot['team_name']=trim($teamName);$snapshot['category_description']=$type['description']??'';$snapshot['people']=(int)($type['people']??1);
            if(isset($linkedQrs[$typeId]))$snapshot['ticket_payment']=array_intersect_key($linkedQrs[$typeId],array_flip(['payment_ticket','label','media','payment_upi','payment_dynamic','payment_name','help']));
            if(az_participation_mode($event)==='performers')$snapshot['participation']='performers';
            $db->prepare('INSERT INTO az_orders(public_id,participant_id,event_id,event_slug,ticket_type,snapshot,answers,quantity,unit_price,amount,state,environment,provider,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')->execute([(json_decode((az_checkout_draft((int)$current['id'],(int)$event['id'],$draftContext)['state_json']??'{}'),true)['payment_reference']??('ORDER-'.strtoupper(bin2hex(random_bytes(8))))),$current['id'],$event['id'],$slug,$typeId,json_encode($snapshot,JSON_THROW_ON_ERROR),'{}',$quantity,$type['price'],$type['price']*$quantity,'FORM_PENDING','live','form',time()+86400,$now,$now]);
            $editId=(int)$db->lastInsertId();
            $db->prepare('INSERT INTO az_form_responses(order_id,raw_answers,schema_json,settings_json) VALUES(?,?,?,?)')->execute([$editId,'{}',json_encode(az_registration_fields($fields),JSON_THROW_ON_ERROR),json_encode($settings,JSON_THROW_ON_ERROR)]);
        }
        $db->prepare('UPDATE az_registration_files SET active=0 WHERE id IN (SELECT file_id FROM az_draft_files WHERE participant_id=? AND event_id=? AND context_id=?)')->execute([$current['id'],$event['id'],$draftContext]);
        $validated=array_replace($validated,az_save_form_uploads($db,$groups,(int)$event['id'],(int)$current['id'],$editId,null,$written));
        if($kind==='team')$validated=['Team name'=>trim($teamName),...$validated];
        az_finish_checkout_draft($db,(int)$current['id'],(int)$event['id'],$draftContext,$editId);
        [$score,$maximum]=!empty($settings['quiz'])?az_form_score(az_registration_fields($fields),$validated):[0,0];
        // Only retain answers to visible items; never persist hidden branch data supplied by a client.
        $raw=[];foreach(az_visible_form_fields($fields,$answers,'registration',$gameId) as $field){$id=$field['id'];if(isset($answers[$id]))$raw[$id]=$answers[$id];if(!empty($field['other'])&&isset($answers[$id.'-other']))$raw[$id.'-other']=$answers[$id.'-other'];}
        $db->prepare("UPDATE az_orders SET answers=?,state='FORM_PENDING',expires_at=?,updated_at=? WHERE id=?")->execute([json_encode($validated,JSON_THROW_ON_ERROR),time()+86400,$now,$editId]);
        $db->prepare('UPDATE az_form_responses SET raw_answers=?,score=?,max_score=?,revision=revision+1 WHERE order_id=?')->execute([json_encode($raw,JSON_THROW_ON_ERROR),$score,$maximum,$editId]);
        $response=az_form_response($editId);
        az_notify_order89(az_order($editId),'registration_received');
        $db->commit();return az_order($editId);
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();foreach($written as $path)@unlink($path);throw $error;}
}
function az_review_form_order(array $actor,int $id,string $decision,array $input): array {
    if(!in_array($decision,['approve','correct','decline'],true))throw new InvalidArgumentException('Choose approve, correction or decline.');
    $note=az_setup_text($input,'note',1000);if($decision!=='approve'&&mb_strlen($note)<3)throw new InvalidArgumentException('Give the participant a reason.');
    $db=cms_db();$db->beginTransaction();
    try{
        az_lock($db);$actor=st_refresh_user($actor);
        if($actor['must_change_password']||!cms_can($actor,'submissions','edit')||!cms_can($actor,'tickets','view'))throw new RuntimeException('No form review access.');
        $order=st_require_order($actor,$id);$response=az_form_response($id);
        if($order['provider']!=='form'||!$response)throw new RuntimeException('This is not a form registration.');
        if($decision==='approve'&&$order['state']==='PAID'){$db->commit();return $order;}
        if((int)($input['revision']??0)!==(int)$response['revision'])throw new RuntimeException('The response changed. Reload before reviewing.');
        if(!in_array($order['state'],['FORM_PENDING','PAID_REVIEW'],true))throw new RuntimeException('This response is not awaiting review.');
        if($order['state']==='PAID_REVIEW'&&$decision!=='approve')throw new RuntimeException('Payment is already confirmed. Resolve capacity before issuing the ticket.');
        $schema=json_decode($response['schema_json'],true);$hasPayment=(int)$order['amount']>0;
        foreach(az_visible_form_fields(['registration_form'=>$response['schema_json'],'_ticket_id'=>$order['ticket_type'],'_ticket_price'=>(int)$order['amount']],json_decode($response['raw_answers'],true)?:[],'registration',(json_decode($order['snapshot'],true)['game_id']??'')) as $field)if(($field['purpose']??'')==='payment')$hasPayment=true;
        $now=gmdate('c');$state=$decision==='correct'?'FORM_CORRECTION':'FORM_DECLINED';
        if($decision==='approve'){
            if($hasPayment){
                if(!cms_can($actor,'payments','verify')||($input['bank_confirmed']??'')!=='yes')throw new RuntimeException('Check the screenshot against the receiving account and confirm the transaction.');
                $reference=az_setup_text($input,'reference',100);if(mb_strlen($reference)<6)throw new InvalidArgumentException('Enter the verified transaction reference.');
                $received=st_finance_amount(az_setup_text($input,'received_amount',20),true);
                if($received!==(int)$order['amount'])throw new RuntimeException('The received amount must match the pass total.');
                $hash=hash('sha256',strtoupper(preg_replace('/[^A-Z0-9]/i','',$reference)));
                $q=$db->prepare('SELECT order_id FROM az_form_payment_refs WHERE reference_hash=?');$q->execute([$hash]);$claimed=$q->fetchColumn();
                if($claimed&&(int)$claimed!==$id)throw new RuntimeException('That transaction reference already approved another registration.');
                foreach($db->query("SELECT order_id,reference FROM az_manual_payments WHERE status='APPROVED'") as $legacy)if((int)$legacy['order_id']!==$id&&hash_equals($hash,hash('sha256',strtoupper(preg_replace('/[^A-Z0-9]/i','',$legacy['reference'])))))throw new RuntimeException('That transaction reference already approved another registration.');
                if(!$claimed)$db->prepare('INSERT INTO az_form_payment_refs(reference_hash,order_id,reference) VALUES(?,?,?)')->execute([$hash,$id,$reference]);
                if(!az_manual_payment($id)){
                    $method=['id'=>'form-payment','kind'=>'other','label'=>'Payment instructions in registration form','recipient'=>$order['event_slug'],'instructions'=>'Coordinator verified the submitted evidence against the receiving account.','qr'=>''];
                    $ticketPayment=json_decode($order['snapshot'],true)['ticket_payment']??null;
                    if($ticketPayment){$method['recipient']=($ticketPayment['payment_name']??'')?:$method['recipient'];$method['label']=$ticketPayment['label'];$method['qr']=$ticketPayment['media'];$method['instructions']=$ticketPayment['help'];$method['upi']=$ticketPayment['payment_upi'];if($method['upi']!=='')$method['kind']='upi';}
                    $db->prepare("INSERT INTO az_manual_payments(order_id,method_snapshot,reference,status,received_amount,reviewed_by,reviewed_at,review_note,created_at) VALUES(?,?,?,'APPROVED',?,?,?,?,?)")->execute([$id,json_encode($method),$reference,$received,$actor['id'],$now,$note,$now]);
                }
            }
            $event=cms_record((int)$order['event_id']);$type=null;foreach(az_prices($event['fields']??[]) as $option)if($option['id']===$order['ticket_type'])$type=$option;
            $available=$type&&(!$type['capacity']||az_reserved((int)$order['event_id'],$order['ticket_type'],'live',$id)+(int)$order['quantity']<=$type['capacity']);
            $state=$available?'PAID':'PAID_REVIEW';
        }
        $db->prepare('UPDATE az_orders SET state=?,provider_state=?,updated_at=?,expires_at=0 WHERE id=?')->execute([$state,'form_'.$decision,$now,$id]);
        $db->prepare('UPDATE az_form_responses SET review_note=?,reviewed_by=?,reviewed_at=?,revision=revision+1 WHERE order_id=?')->execute([$note,$actor['id'],$now,$id]);
        $db->prepare('INSERT INTO az_form_reviews(order_id,staff_id,action,note,revision,created_at) VALUES(?,?,?,?,?,?)')->execute([$id,$actor['id'],$decision,$note,$response['revision'],$now]);
        if($state==='PAID')az_issue_tickets(az_order($id));
        elseif($decision==='decline')az_notify_order89(az_order($id),'ticket_rejected','form:'.((int)$response['revision']+1),['note'=>$note,'rejection_type'=>'registration','form_revision'=>(int)$response['revision']+1,'cta'=>'Review your registration']);
        st_event_audit($actor,(int)$order['event_id'],'form.'.$decision,$order['public_id'].' · '.$note);$db->commit();return az_order($id);
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
}
