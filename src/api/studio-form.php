<?php
declare(strict_types=1);
require_once __DIR__.'/../includes/commerce.php';
set_security_headers();header('Content-Type: application/json');header('Cache-Control: no-store');
$db=cms_db();
try{
    if($_SERVER['REQUEST_METHOD']!=='POST')throw new RuntimeException('Use POST.');
    $body=file_get_contents('php://input',false,null,0,600001);
    if(strlen($body)>600000)throw new RuntimeException('Keep the form below 600 KB.');
    $input=json_decode($body,true,64,JSON_THROW_ON_ERROR);
    if(!is_array($input)||!is_string($input['csrf_token']??null)||!csrf_verify($input['csrf_token']))throw new RuntimeException('Your session expired. Reload the editor.');
    $phase=$input['phase']??'';if(!in_array($phase,['interest','registration'],true))throw new RuntimeException('Choose a form.');
    $publish=($input['action']??'')==='publish';
    if(!in_array($input['action']??'',['draft','publish'],true))throw new RuntimeException('Choose save draft or publish.');
    $payload=$input['form']??null;
    if(!is_array($payload)||!is_array($payload['questions']??null)||count($payload['questions'])>100||!is_array($payload['settings']??null))throw new RuntimeException('Invalid form draft.');
    foreach(['title'=>200,'intro'=>5000,'button'=>200] as $key=>$limit)if(!is_string($payload[$key]??null)||mb_strlen($payload[$key])>$limit)throw new RuntimeException('Check the form '.$key.'.');
    foreach($payload['questions'] as &$row){
        if(!is_array($row))throw new RuntimeException('Invalid question.');
        if(!is_string($row['type']??null)||!isset(az_form_types()[$row['type']]))throw new RuntimeException('Choose a supported question type.');
        foreach(['id'=>60,'label'=>120,'help'=>2000,'placeholder'=>120,'game'=>60,'condition_field'=>60,'condition_value'=>120,'media'=>500,'payment_upi'=>120,'payment_name'=>80,'payment_ticket'=>60,'file_types'=>20,'purpose'=>20,'min'=>20,'max'=>20,'validation'=>20,'validation_value'=>120,'validation_message'=>200,'low_label'=>60,'high_label'=>60,'feedback'=>500] as $key=>$limit)az_setup_text($row,$key,$limit);
        if($publish&&(!is_string($row['label']??null)||trim($row['label'])===''))throw new RuntimeException('Add a title to every question before publishing.');
        foreach(['options','rows','allowed_values','answer_key'] as $key)$row[$key]=az_form_lines($row[$key]??'', $key==='allowed_values'?500:($key==='rows'?25:50));
        foreach(['required','other','shuffle'] as $key){if($publish){if(empty($row[$key]))unset($row[$key]);else $row[$key]='1';}else $row[$key]=!empty($row[$key]);}
    }unset($row);
    $payload['settings']=json_decode(az_validate_form_settings(array_filter($payload['settings'],fn($v)=>$v!==false&&$v!==null)),true);
    $db->beginTransaction();az_lock($db);$staff=cms_user();if(!$staff)throw new RuntimeException('Sign in to Studio.');$staff=st_refresh_user($staff);
    $event=cms_record((int)($input['event_id']??0));
    if($staff['must_change_password']||!$event||$event['type']!=='event'||!cms_can($staff,'event','edit',$event))throw new RuntimeException('No editing access to this event.');
    if($phase==='interest'&&az_participation_mode($event)==='contribution')throw new RuntimeException('Use the contribution form for this event.');
    if($phase==='registration'&&az_participation_mode($event)==='registration')$payload['settings']['one_response']=true;
    if((int)($input['revision']??0)!==(int)$event['revision']){http_response_code(409);throw new RuntimeException('This event changed in another editor. Download your template, then reload before saving.');}
    $baseFields=$event['fields'];$gameId=az_setup_text($input,'game',60);$fields=az_game_fields81($baseFields,$gameId,$phase);unset($fields['_event_slug']);
    if(!empty($payload['prices'])&&$phase!=='registration')throw new RuntimeException('Ticket prices belong to registration forms.');
    $priced=az_form_prices108($fields,$payload['prices']??[],$gameId);
    if($publish){
        $fields['ticket_types']=$priced['ticket_types'];
        if(!cms_can($staff,'event','publish',$event))throw new RuntimeException('Your role can save a draft for an editor to publish.');
        if(trim($payload['title'])==='')throw new RuntimeException('Add a form title before publishing.');
        if($gameId!=='')foreach($payload['questions'] as &$row){$row['game']='';}unset($row);
        $fields[$phase.'_form']=az_validate_registration_fields($payload['questions'],$gameId===''?az_event_games($fields,false):[]);
        az_validate_ticket_qrs85($fields,$phase);
        $fields[$phase.'_settings']=json_encode($payload['settings'],JSON_THROW_ON_ERROR);
        foreach(['title','intro','button'] as $key)$fields[$phase.'_'.$key]=trim($payload[$key]);
        $fields['form_workflow']='1';unset($fields[$phase.'_form_draft']);
    }else{$fields[$phase.'_form_draft']=$payload;}
    if($gameId!==''){
        $forms=json_decode($baseFields['game_forms']??'{}',true)?:[];
        foreach(['form','settings','title','intro','button','form_draft'] as $suffix){$key=$phase.'_'.$suffix;if(array_key_exists($key,$fields))$forms[$gameId][$key]=$fields[$key];else unset($forms[$gameId][$key]);}
        if($publish)$baseFields['ticket_types']=$fields['ticket_types'];
        $baseFields['game_forms']=json_encode($forms,JSON_THROW_ON_ERROR);if($publish)$baseFields['form_workflow']='1';$fields=$baseFields;
    }
    unset($fields['_form_game'],$fields['_form_game_label'],$fields['_event_slug']);
    $q=$db->prepare('UPDATE cms_content SET data=?,revision=revision+1,updated_at=? WHERE id=? AND revision=?');
    $q->execute([json_encode($fields,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR),gmdate('c'),$event['id'],$event['revision']]);
    if(!$q->rowCount())throw new RuntimeException('The event changed. Reload before saving.');
    if($publish){st_event_audit($staff,(int)$event['id'],'form.publish',ucfirst($phase).' form');cms_audit($staff,'form.publish',$event['title'].' · '.$phase);}
    $db->commit();echo json_encode(['ok'=>true,'revision'=>(int)$event['revision']+1,'published'=>$publish]);
}catch(Throwable $error){if($db->inTransaction())$db->rollBack();if(http_response_code()<400)http_response_code(400);echo json_encode(['ok'=>false,'error'=>$error instanceof PDOException?'The form could not be saved.':$error->getMessage()]);}
