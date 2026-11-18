<?php
declare(strict_types=1);

function az_install_progress79(PDO $db): void {
    if($db->query("SELECT value FROM cms_settings WHERE setting_key='registration_progress79'")->fetchColumn())return;
    $text=$db->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite'?'TEXT':'MEDIUMTEXT';
    $db->exec("CREATE TABLE IF NOT EXISTS az_checkout_drafts (participant_id INT NOT NULL,event_id INT NOT NULL,context_id INT NOT NULL DEFAULT 0,answers_json $text NOT NULL,game_id VARCHAR(60) NOT NULL DEFAULT '',team_name VARCHAR(120) NOT NULL DEFAULT '',schema_hash VARCHAR(64) NOT NULL,revision INT NOT NULL DEFAULT 0,updated_at VARCHAR(40) NOT NULL,PRIMARY KEY(participant_id,event_id,context_id))");
    $db->exec('CREATE TABLE IF NOT EXISTS az_draft_files (file_id INT PRIMARY KEY,participant_id INT NOT NULL,event_id INT NOT NULL,context_id INT NOT NULL DEFAULT 0)');
    $db->beginTransaction();
    try{
        az_lock($db);
        if($db->query("SELECT value FROM cms_settings WHERE setting_key='registration_progress79'")->fetchColumn()){$db->commit();return;}
        foreach($db->query("SELECT id,slug,data FROM cms_content WHERE type='event'")->fetchAll() as $event){
            $fields=json_decode($event['data'],true)?:[];
            $fields['registration_kind']=$fields['registration_kind']??($event['slug']==='treasure-hunt'?'team':'individual');
            if(in_array($event['slug'],['inauguration','cultural-night'],true)){
                $fields['registration_mode']='open';$fields['registration_opens']='';$fields['registration_closes']='';
                $fields['registration_title']='Contribute to '.$event['slug'];$fields['registration_button']='Send contribution';
                $fields['registration_intro']='Tell the coordinators how you would like to contribute or perform.';
                $fields['registration_note']='Share your contribution with the event coordinators.';
                $fields['registration_closed_message']='Contributions are currently closed. Contact the event coordinators.';
                $fields['registration_settings']=json_encode(['accepting'=>true,'one_response'=>true,'allow_edit'=>false,'progress'=>true,'confirmation'=>'Thank you. Your contribution has been sent to the event team.']);
                if(empty($fields['registration_form']))$fields['registration_form']=json_encode([
                    ['id'=>'phone','label'=>'Contact number','type'=>'tel','required'=>true,'options'=>[]],
                    ['id'=>'contribution','label'=>'How would you like to contribute or perform?','type'=>'textarea','required'=>true,'options'=>[]]
                ]);
                $fields=az_participation_fields($event['slug'],$fields);unset($fields['_event_slug']);
            }
            $db->prepare('UPDATE cms_content SET data=?,revision=revision+1 WHERE id=?')->execute([json_encode($fields,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR),$event['id']]);
        }
        az_schema_marker($db,'registration_progress79');$db->commit();
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
}
function az_install_autosave88(PDO $db): void {
    if($db->query("SELECT value FROM cms_settings WHERE setting_key='registration_autosave88'")->fetchColumn())return;
    $sqlite=$db->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite';
    $columns=$sqlite?$db->query('PRAGMA table_info(az_checkout_drafts)')->fetchAll():$db->query('SHOW COLUMNS FROM az_checkout_drafts')->fetchAll();
    $names=array_column($columns,$sqlite?'name':'Field');
    if(!in_array('state_json',$names,true))$db->exec('ALTER TABLE az_checkout_drafts ADD COLUMN state_json TEXT NULL');
    if(!in_array('request_id',$names,true))$db->exec("ALTER TABLE az_checkout_drafts ADD COLUMN request_id VARCHAR(80) NOT NULL DEFAULT ''");
    az_schema_marker($db,'registration_autosave88');
}
function az_existing_event_order(int $participantId,int $eventId,string $game=''): ?array {
    $q=cms_db()->prepare("SELECT * FROM az_orders WHERE participant_id=? AND event_id=? AND environment='live' ORDER BY CASE WHEN state IN ('PAID','PAID_REVIEW') THEN 0 ELSE 1 END,id DESC");
    $q->execute([$participantId,$eventId]);
    foreach($q as $order){$registeredGame=json_decode($order['snapshot'],true)['game_id']??'';if($order['event_slug']==='joystick'&&($game===''||($registeredGame!==''&&$registeredGame!==$game)))continue;return $order;}return null;
}
function az_duplicate_registration_message(array $order): string {
    $target=$order['event_slug']==='joystick'?'this game':'this event';
    return (in_array($order['state'],['PAID','PAID_REVIEW'],true)?'You have already got your ticket for '.$target.'.':'You have already registered for '.$target.'.').' Please reach our team for more details.';
}
/** Resolve a published category and take its price only from the server. */
function az_registration_entry(array $fields,string $gameId='',string $typeId=''): ?array {
    $options=az_ticket_options81($fields,$gameId);
    if($typeId!==''){foreach($options as $option)if($option['id']===$typeId)return $option;return null;}
    return count($options)===1?$options[0]:null;
}
function az_single_entry_prices(array $fields,array $previous,array $input): string {
    $capacity=filter_var($input['registration_capacity']??0,FILTER_VALIDATE_INT);
    if($capacity===false||$capacity<0||$capacity>1000000)throw new InvalidArgumentException('Use a capacity from 0 to 1000000.');
    $rows=az_prices($previous);$first=az_registration_entry($previous)??($rows[0]??['id'=>'standard-entry']);
    $new=['id'=>$first['id'],'label'=>($fields['registration_kind']??'individual')==='team'?'Team ticket':'Individual ticket','price'=>az_inr_to_paise($fields['registration_fee']??'0'),'capacity'=>$capacity,'active'=>true,'game'=>''];
    $out=[$new];foreach($rows as $row)if($row['id']!==$new['id']){$row['active']=false;$out[]=$row;}
    return json_encode($out,JSON_THROW_ON_ERROR);
}
function az_draft_context(array $participant,array $event,int $editId=0,string $game=''): array {
    $fields=$event['fields'];$order=null;
    if(az_participation_mode($event)!=='registration')throw new RuntimeException('This event does not take ticket registrations.');
    if($editId){
        $order=az_order($editId);$response=$order?az_form_response($editId):null;
        if(!$order||!$response||(int)$order['participant_id']!==(int)$participant['id']||(int)$order['event_id']!==(int)$event['id'])throw new RuntimeException('Response unavailable.');
        $settings=json_decode($response['settings_json'],true)?:[];
        if(!in_array($order['state'],['FORM_PENDING','FORM_CORRECTION'],true)||($order['state']!=='FORM_CORRECTION'&&empty($settings['allow_edit'])))throw new RuntimeException('This response is locked for review.');
        $fields['registration_form']=$response['schema_json'];
    }else{
        az_selected_game($fields,$game);$fields=az_game_fields81($fields,$game);
        if($existing=az_existing_event_order((int)$participant['id'],(int)$event['id'],$game))throw new RuntimeException(az_duplicate_registration_message($existing));
        if(cms_event_phase($fields)!=='open'||!az_form_settings($fields)['accepting'])throw new RuntimeException('Registration is closed.');
    }
    return [$fields,$order];
}
function az_checkout_draft(int $participantId,int $eventId,int $context=0): ?array {
    $q=cms_db()->prepare('SELECT * FROM az_checkout_drafts WHERE participant_id=? AND event_id=? AND context_id=?');$q->execute([$participantId,$eventId,$context]);return $q->fetch()?:null;
}
function az_checkout_draft_files(int $participantId,int $eventId,int $context=0): array {
    $q=cms_db()->prepare('SELECT f.* FROM az_registration_files f JOIN az_draft_files d ON d.file_id=f.id WHERE d.participant_id=? AND d.event_id=? AND d.context_id=? AND f.active=1 ORDER BY f.id');$q->execute([$participantId,$eventId,$context]);return $q->fetchAll();
}
function az_draft_schema_hash(array $fields): string { return hash('sha256',json_encode(az_registration_fields($fields),JSON_THROW_ON_ERROR)); }
function az_draft_result88(array $draft,int $participant,int $event,int $context): array {
    return ['revision'=>(int)$draft['revision'],'updated_at'=>$draft['updated_at'],'files'=>array_map(fn($file)=>array_intersect_key($file,array_flip(['id','field_id','label','original_name'])),az_checkout_draft_files($participant,$event,$context))];
}
/** Partial answers need not pass required-field checks, but their shape and size are bounded. */
function az_partial_answers(array $fields,array $answers): array {
    if(strlen(json_encode($answers,JSON_THROW_ON_ERROR))>250000)throw new InvalidArgumentException('The draft is too large.');
    $clean=[];
    $check=function($value,int $depth=0)use(&$check){
        if(is_string($value)){if(mb_strlen($value)>10000||str_contains($value,"\0"))throw new InvalidArgumentException('Check the draft answers.');return $value;}
        if(!is_array($value)||$depth>1||count($value)>50)throw new InvalidArgumentException('Check the draft answers.');
        return array_map(fn($v)=>$check($v,$depth+1),$value);
    };
    foreach(az_registration_fields($fields) as $field)if(!az_form_layout($field['type'])&&$field['type']!=='file'){
        foreach([$field['id'],...(!empty($field['other'])?[$field['id'].'-other']:[])] as $key)if(array_key_exists($key,$answers))$clean[$key]=$check($answers[$key]);
    }
    return $clean;
}
function az_save_checkout_draft(array $participant,array $event,array $input,array $files): array {
    az_limit('registration-draft',(string)$participant['id'],120,900);
    $written=[];$db=cms_db();$db->beginTransaction();
    try{
        az_lock($db);$participant=az_participant();if(!$participant||empty($participant['profile_completed'])||!$participant['email_verified'])throw new RuntimeException('Sign in with a verified account to save your progress.');
        $edit=(int)($input['edit_order']??0);$game=az_setup_text($input,'game',60);
        [$fields,$order]=az_draft_context($participant,az_event($event['slug']),$edit,$game);
        if($order)$game=(json_decode($order['snapshot'],true)['game_id']??'');
        $context=az_draft_context81($game,$edit);
        $draft=az_checkout_draft((int)$participant['id'],(int)$event['id'],$context);$version=(int)($input['draft_revision']??0);
        $request=az_setup_text($input,'draft_request',80);
        if($request!==''&&!preg_match('/^[a-zA-Z0-9_-]{1,80}$/D',$request))throw new InvalidArgumentException('Invalid draft request.');
        // A connection can fail after the transaction commits. Retrying that same
        // request acknowledges its saved revision without uploading files twice.
        if($draft&&$request!==''&&hash_equals((string)($draft['request_id']??''),$request)){
            $result=az_draft_result88($draft,(int)$participant['id'],(int)$event['id'],$context);$db->commit();return $result;
        }
        if($version!==(int)($draft['revision']??0))throw new RuntimeException('Your draft changed in another tab. Reload to continue with the latest saved details.');
        $answers=az_partial_answers($fields,is_array($input['answers']??null)?$input['answers']:[]);
        $team=az_setup_text($input,'team_name',120);$type=az_setup_text($input,'type',60);
        if($order)$type=$order['ticket_type'];elseif($type!==''&&!az_registration_entry($fields,$game,$type))throw new RuntimeException('Choose an available ticket category.');
        $method=az_setup_text($input,'payment_method',60);
        if($method!==''&&!in_array($method,array_column(az_payment_methods($fields),'id'),true))throw new InvalidArgumentException('Choose an available payment account.');
        $savedState=json_decode($draft['state_json']??'{}',true)?:[];
        $state=json_encode(['consent'=>($input['consent']??'')==='yes','payment_method'=>$method,'payment_reference'=>$savedState['payment_reference']??('ORDER-'.strtoupper(bin2hex(random_bytes(8))))],JSON_THROW_ON_ERROR);
        // Keep unfinished branch answers and attachments in the private draft.
        // Final submission still validates and includes only the visible branch.
        $schema=az_registration_fields($fields);foreach($schema as &$field){$field['required']=false;unset($field['condition_field'],$field['condition_value']);}unset($field);$optional=$fields;unset($optional['_ticket_id'],$optional['_ticket_price']);$optional['registration_form']=json_encode($schema);
        $retained=az_checkout_draft_files((int)$participant['id'],(int)$event['id'],$context);
        $groups=az_collect_form_uploads($optional,$answers,$files,'registration',$game,$retained);
        $db->prepare('UPDATE az_registration_files SET active=0 WHERE id IN (SELECT file_id FROM az_draft_files WHERE participant_id=? AND event_id=? AND context_id=?)')->execute([$participant['id'],$event['id'],$context]);
        az_save_form_uploads($db,$groups,(int)$event['id'],(int)$participant['id'],null,null,$written);
        // New files belong to this request, never to IDs posted by the browser.
        $insert=$db->prepare('INSERT INTO az_draft_files(file_id,participant_id,event_id,context_id) VALUES(?,?,?,?)');
        foreach($written as $path){$q=$db->prepare('SELECT id FROM az_registration_files WHERE filename=?');$q->execute([basename($path)]);$insert->execute([$q->fetchColumn(),$participant['id'],$event['id'],$context]);}
        $now=gmdate('c');$hash=az_draft_schema_hash($fields);
        if($draft)$db->prepare('UPDATE az_checkout_drafts SET answers_json=?,game_id=?,team_name=?,type_id=?,schema_hash=?,state_json=?,request_id=?,revision=revision+1,updated_at=? WHERE participant_id=? AND event_id=? AND context_id=?')->execute([json_encode($answers),$game,$team,$type,$hash,$state,$request,$now,$participant['id'],$event['id'],$context]);
        else $db->prepare('INSERT INTO az_checkout_drafts(participant_id,event_id,context_id,answers_json,game_id,team_name,type_id,schema_hash,state_json,request_id,revision,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,1,?)')->execute([$participant['id'],$event['id'],$context,json_encode($answers),$game,$team,$type,$hash,$state,$request,$now]);
        $result=az_draft_result88(['revision'=>$version+1,'updated_at'=>$now],(int)$participant['id'],(int)$event['id'],$context);$db->commit();return $result;
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();foreach($written as $path)@unlink($path);throw $error;}
}
function az_finish_checkout_draft(PDO $db,int $participantId,int $eventId,int $context,int $orderId): void {
    $db->prepare('UPDATE az_registration_files SET order_id=? WHERE active=1 AND id IN (SELECT file_id FROM az_draft_files WHERE participant_id=? AND event_id=? AND context_id=?)')->execute([$orderId,$participantId,$eventId,$context]);
    $db->prepare('DELETE FROM az_draft_files WHERE participant_id=? AND event_id=? AND context_id=?')->execute([$participantId,$eventId,$context]);
    $db->prepare('DELETE FROM az_checkout_drafts WHERE participant_id=? AND event_id=? AND context_id=?')->execute([$participantId,$eventId,$context]);
}
