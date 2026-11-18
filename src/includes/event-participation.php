<?php
declare(strict_types=1);

/** These two programme items have fixed participation rules, including for direct API calls. */
function az_participation_mode(array $event): string {
    $slug=$event['slug']??$event['_event_slug']??'';
    return in_array($slug,['inauguration','cultural-night'],true)?'contribution':'registration';
}

function az_participation_fields(string $slug,array $fields): array {
    $fields['_event_slug']=$slug;
    $mode=az_participation_mode($fields);
    if($mode==='registration')return $fields;
    if($mode==='contribution'){
        $fields['registration_fee']='0';$fields['ticket_types']='[]';$fields['payment_methods']='[]';$fields['game_categories']='[]';
        $fields['registration_url']='';$fields['form_workflow']='1';
        return $fields;
    }
    $fields['registration_fee']='0';$fields['payment_methods']='[]';$fields['game_categories']='[]';
    $fields['interest_open']='0';$fields['registration_url']='';
    if($mode==='ceremony'){
        $fields['registration_mode']='none';$fields['ticket_types']='[]';$fields['fees']='No registration required';
    }else{
        $fields['fees']='Free for performers';
        $fields['ticket_types']='[{"id":"performer-pass","label":"Performer ticket","price":0,"capacity":0,"active":true}]';
        $fields['registration_title']=$fields['registration_title']??'Your performance';$fields['registration_button']=$fields['registration_button']??'Submit performer application';
        $fields['registration_intro']=$fields['registration_intro']??'';
        $fields['registration_note']='Performing is free. The coordinators review applications and issue tickets to confirmed performers.';
        $fields['registration_form']=$fields['registration_form']??json_encode([
            ['id'=>'phone','label'=>'Contact number','type'=>'tel','required'=>true,'options'=>[]],
            ['id'=>'performance','label'=>'What would you like to perform?','type'=>'textarea','required'=>true,'options'=>[]],
        ],JSON_THROW_ON_ERROR);
    }
    return $fields;
}

/** Update current setup once; retain past applications, payment records and issued tickets. */
function az_install_participation66(PDO $db): void {
    if($db->query("SELECT value FROM cms_settings WHERE setting_key='event_participation_66'")->fetchColumn())return;
    $db->beginTransaction();
    try{
        az_lock($db);
        if($db->query("SELECT value FROM cms_settings WHERE setting_key='event_participation_66'")->fetchColumn()){$db->commit();return;}
        foreach(['inauguration','cultural-night'] as $slug){
            $query=$db->prepare("SELECT id,data FROM cms_content WHERE type='event' AND slug=?");$query->execute([$slug]);$row=$query->fetch();
            if(!$row)continue;
            $fields=json_decode($row['data'],true)?:[];
            if($slug==='cultural-night'){
                $fields['registration_mode']='open';$fields['registration_opens']='';$fields['registration_closes']='';
                $fields['registration_closed_message']='Performer applications are currently closed. Contact the Cultural Night coordinators.';
            }
            $fields=az_participation_fields($slug,$fields);unset($fields['_event_slug']);
            $db->prepare('UPDATE cms_content SET data=?,revision=revision+1,updated_at=? WHERE id=?')->execute([json_encode($fields,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR),gmdate('c'),$row['id']]);
        }
        az_schema_marker($db,'event_participation_66');$db->commit();
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
}

/** Confirmation is event-scoped and atomic with issuance; repeating it cannot issue extra tickets. */
function az_review_performer(array $actor,int $id,string $decision): array {
    if(!in_array($decision,['confirm','decline'],true))throw new InvalidArgumentException('Choose confirm or decline.');
    $db=cms_db();$db->beginTransaction();
    try{
        az_lock($db);$actor=st_refresh_user($actor);
        if($actor['must_change_password']||!cms_can($actor,'submissions','edit')||!cms_can($actor,'tickets','view'))throw new RuntimeException('No performer review access.');
        $order=st_require_order($actor,$id);$snapshot=json_decode($order['snapshot'],true)?:[];
        if($order['event_slug']!=='cultural-night'||($snapshot['participation']??'')!=='performers'||$order['provider']!=='free'||(int)$order['amount']!==0)throw new RuntimeException('This is not a free performer application.');
        $target=$decision==='confirm'?'PAID':'PERFORMER_DECLINED';
        if($order['state']===$target){$db->commit();return $order;}
        if($order['state']!=='PERFORMER_PENDING')throw new RuntimeException('This application has already been reviewed. Reload the performer list.');
        $participant=$db->prepare('SELECT id FROM az_participants WHERE id=? AND active=1 AND email_verified=1');$participant->execute([$order['participant_id']]);
        if($decision==='confirm'&&!$participant->fetchColumn())throw new RuntimeException('The performer account must be active and verified.');
        $db->prepare('UPDATE az_orders SET state=?,provider_state=?,updated_at=? WHERE id=?')->execute([$target,'performer_'.$decision,gmdate('c'),$id]);
        $order=az_order($id);if($decision==='confirm')az_issue_tickets($order);
        st_event_audit($actor,(int)$order['event_id'],'performer.'.$decision,$order['public_id']);
        $db->commit();return $order;
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
}
