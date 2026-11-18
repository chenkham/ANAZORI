<?php
declare(strict_types=1);

const ANAZORI_NOTICE_KINDS101=['registration_received','ticket_confirmed','event_reminder'];

final class AzMailNotDue101 extends RuntimeException {
    public function __construct(public readonly int $sendAt){parent::__construct('The event reminder is not due yet.');}
}

function az_reminder_hours101(array $fields): int {
    return ($fields['reminder_window']??'24h')==='12h'?12:24;
}

/** Accept fixed event dates only, using India time when no offset is supplied. */
function az_event_start101(array $fields): ?int {
    $value=trim((string)($fields['starts_at']??''));
    if(!preg_match('/^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:\d{2})?)?$/D',$value))return null;
    try{
        $date=new DateTimeImmutable($value,new DateTimeZone('Asia/Kolkata'));
        $errors=DateTimeImmutable::getLastErrors();
        return $errors&&($errors['warning_count']||$errors['error_count'])?null:$date->getTimestamp();
    }catch(Throwable){return null;}
}

/** Once per approved order and published start, at the event's selected lead time. */
function az_schedule_reminders89(int $now): int {
    if(!az_mail_notifications_enabled89())return 0;
    $db=cms_db();$added=0;
    foreach($db->query("SELECT * FROM cms_content WHERE type='event' AND status='PUBLISHED'")->fetchAll() as $record){
        $event=cms_unpack($record);$fields=$event['fields'];$start=az_event_start101($fields);
        if(!$start||$start<=$now||cms_event_phase($fields)==='completed')continue;
        $due=$start-az_reminder_hours101($fields)*3600;
        $reschedule=$db->prepare("UPDATE az_mail_jobs89 SET available_at=? WHERE kind='event_reminder' AND event_time=? AND status='pending' AND last_error='reminder_not_due' AND order_id IN (SELECT id FROM az_orders WHERE event_id=?)");
        $reschedule->execute([max($now,$due),$start,$event['id']]);
        if($due>$now)continue;
        $query=$db->prepare("SELECT o.*,t.ticket_id FROM az_orders o JOIN az_tickets t ON t.order_id=o.id WHERE o.event_id=? AND o.environment='live' AND o.state='PAID' AND t.status='VALID' AND NOT EXISTS(SELECT 1 FROM az_mail_jobs89 j WHERE j.order_id=o.id AND j.kind='event_reminder' AND j.event_time=?) ORDER BY o.id LIMIT 200");
        $query->execute([$event['id'],$start]);
        foreach($query->fetchAll() as $order){
            $personQuery=$db->prepare('SELECT id,name,email FROM az_participants WHERE id=? AND active=1 AND email_verified=1');
            $personQuery->execute([$order['participant_id']]);$person=$personQuery->fetch();if(!$person)continue;
            $snapshot=json_decode($order['snapshot'],true)?:[];
            $data=['email'=>$person['email'],'name'=>$person['name'],'event'=>$event['title'],'game'=>$snapshot['game']??'','category'=>$snapshot['type']??'','people'=>(string)($snapshot['people']??1),'when'=>az_mail_event_time($fields['starts_at']),'venue'=>$fields['venue']?:($snapshot['venue']??''),'ticket'=>$order['ticket_id'],'reference'=>$order['public_id'],'path'=>'/ticket.php?id='.$order['ticket_id'],'event_path'=>'/event.php?name='.$event['slug'],'cta'=>'Open your ticket'];
            az_queue_mail89('reminder:'.$order['id'].':'.$start,'event_reminder',$data,(int)$order['id'],(int)$person['id'],$start);
            $added++;
        }
    }
    return $added;
}

/** Recheck the live decision, ownership and schedule immediately before delivery. */
function az_mail_job_current89(array $job,array $data=[]): bool {
    if(!in_array($job['kind'],ANAZORI_NOTICE_KINDS101,true)||empty($job['order_id'])||empty($job['participant_id']))return false;
    $db=cms_db();$query=$db->prepare('SELECT * FROM az_orders WHERE id=?');$query->execute([$job['order_id']]);$order=$query->fetch();
    if(!$order||$order['environment']!=='live'||(int)$order['participant_id']!==(int)$job['participant_id'])return false;
    $query=$db->prepare('SELECT active,email_verified,email FROM az_participants WHERE id=?');$query->execute([$job['participant_id']]);$person=$query->fetch();
    if(!$person||!$person['active']||!$person['email_verified']||strtolower($person['email'])!==strtolower((string)($data['email']??'')))return false;
    foreach(['form_revision'=>['az_form_responses','order_id'],'payment_revision'=>['az_manual_payments','order_id']] as $key=>[$table,$column]){
        if(!isset($data[$key]))continue;
        $query=$db->prepare('SELECT revision FROM '.$table.' WHERE '.$column.'=?');$query->execute([$order['id']]);
        if((int)$query->fetchColumn()!==(int)$data[$key])return false;
    }
    if($job['kind']==='registration_received')return in_array($order['state'],['FORM_PENDING','FORM_CORRECTION','PERFORMER_PENDING','PENDING_REVIEW'],true);
    if($job['kind']==='ticket_rejected'){
        if(($data['rejection_type']??'')==='ticket'){
            if($order['state']!=='PAID')return false;
            $query=$db->prepare("SELECT b.blocked_at,b.reason FROM az_tickets t JOIN az_ticket_blocks b ON b.ticket_id=t.id WHERE t.order_id=? AND t.ticket_id=? AND t.status='BLOCKED'");
            $query->execute([$order['id'],$data['ticket']??'']);$block=$query->fetch();
            return $block&&$block['blocked_at']===($data['block_stamp']??'')&&hash_equals(hash('sha256',$block['reason']),(string)($data['block_reason_hash']??''));
        }
        return in_array($order['state'],['FORM_DECLINED','PERFORMER_DECLINED','REJECTED'],true);
    }
    if($order['state']!=='PAID')return false;
    $query=$db->prepare("SELECT ticket_id,status FROM az_tickets WHERE order_id=? AND status IN ('VALID','USED')");
    $query->execute([$order['id']]);$tickets=$query->fetchAll();
    if(!$tickets)return false;
    if(isset($data['ticket'])&&!in_array($data['ticket'],array_column($tickets,'ticket_id'),true))return false;
    if($job['kind']==='event_reminder'){
        $valid=array_filter($tickets,fn($ticket)=>$ticket['status']==='VALID'&&(!isset($data['ticket'])||$ticket['ticket_id']===$data['ticket']));
        if(!$valid)return false;
        $record=cms_record((int)$order['event_id']);
        if(!$record||$record['status']!=='PUBLISHED'||cms_event_phase($record['fields'])==='completed')return false;
        $start=az_event_start101($record['fields']);$now=time();
        if(!$start||$start<=$now||$start!==(int)$job['event_time'])return false;
        $due=$start-az_reminder_hours101($record['fields'])*3600;
        if($due>$now)throw new AzMailNotDue101($due);
    }
    return true;
}

/** Event changes should be reflected in pending notices, including venue edits. */
function az_mail_data_current101(array $job,array $data): array {
    $query=cms_db()->prepare('SELECT event_id,event_slug FROM az_orders WHERE id=?');$query->execute([$job['order_id']]);$order=$query->fetch();
    if(!$order)return $data;
    $event=cms_record((int)$order['event_id']);if(!$event)return $data;
    $fields=$event['fields'];
    $data['event']=$event['title'];$data['when']=az_mail_event_time($fields['starts_at']??'');
    if(trim((string)($fields['venue']??''))!=='')$data['venue']=$fields['venue'];
    $data['event_path']='/event.php?name='.$event['slug'];
    return $data;
}
