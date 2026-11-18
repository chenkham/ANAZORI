<?php
declare(strict_types=1);

function st_workspace_url(string $section,?int $eventId=null,string $environment='live',array $extra=[]): string {
    if($section==='details'){$section='payments';$extra=['view'=>'table',...$extra];}
    return '/admin.php?'.http_build_query(array_merge(['section'=>$section],$eventId?['event_id'=>$eventId]:[],$extra));
}
function st_operation_scope(array $u,?int $eventId,string $column): array {
    if($eventId){st_require_event($u,$eventId);return ['sql'=>st_scope_column($column).'=?','params'=>[$eventId]];}
    return st_scope_sql($u,$column);
}
function st_operation_query(array $u,string $section,?int $eventId,string $environment,string $search='',string $status='',string $gameId=''): array {
    st_finance_environment($environment);
    if(!cms_can($u,$section))throw new RuntimeException('No access to this register.');
    $scope=st_operation_scope($u,$eventId,'o.event_id');$params=[$environment,...$scope['params']];
    if($gameId!==''&&in_array($section,['payments','tickets'],true)){
        if(!preg_match('/^[a-z0-9-]{3,60}$/D',$gameId))throw new InvalidArgumentException('Choose a valid game.');
        $gameColumn=cms_db()->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite'?"json_extract(o.snapshot,'$.game_id')":"JSON_UNQUOTE(JSON_EXTRACT(o.snapshot,'$.game_id'))";
        $scope['sql'].=' AND '.$gameColumn.'=?';$params[]=$gameId;
    }
    if($section==='participants'&&st_has_global_access($u)&&!$eventId){
        $sql='SELECT p.id,p.name,p.email,p.email_verified,p.active,p.created_at,COUNT(DISTINCT o.id) orders,COALESCE(SUM(CASE WHEN o.state=\'PAID\' THEN o.quantity ELSE 0 END),0) entries FROM az_participants p LEFT JOIN az_orders o ON o.participant_id=p.id AND o.environment=?';$params=[$environment];
        if($search){$sql.=' WHERE (p.name LIKE ? OR p.email LIKE ?)';array_push($params,'%'.$search.'%','%'.$search.'%');}
        return ['sql'=>$sql.' GROUP BY p.id,p.name,p.email,p.email_verified,p.active,p.created_at ORDER BY p.id DESC','params'=>$params];
    }
    if($section==='participants'){
        $sql='SELECT p.id,p.name,p.email,p.email_verified,p.active,p.created_at,COUNT(DISTINCT o.id) orders,COALESCE(SUM(CASE WHEN o.state=\'PAID\' THEN o.quantity ELSE 0 END),0) entries FROM az_participants p JOIN az_orders o ON o.participant_id=p.id WHERE o.environment=? AND ('.$scope['sql'].')';
        if($search){$sql.=' AND (p.name LIKE ? OR p.email LIKE ?)';array_push($params,'%'.$search.'%','%'.$search.'%');}
        return ['sql'=>$sql.' GROUP BY p.id,p.name,p.email,p.email_verified,p.active,p.created_at ORDER BY p.id DESC','params'=>$params];
    }
    if($section==='payments'){
        $sql='SELECT o.*,p.name,p.email,m.reference AS payment_reference,m.paid_on,m.status AS review_status,m.method_snapshot,m.proof_id,m.reviewed_by,m.reviewed_at,m.review_note,COALESCE((SELECT SUM(r.amount) FROM az_refunds r WHERE r.order_id=o.id),0) refunded FROM az_orders o JOIN az_participants p ON p.id=o.participant_id LEFT JOIN az_manual_payments m ON m.order_id=o.id WHERE o.environment=? AND ('.$scope['sql'].')';
        if($search){$sql.=' AND (p.name LIKE ? OR p.email LIKE ? OR o.public_id LIKE ? OR m.reference LIKE ?)';array_push($params,...array_fill(0,4,'%'.$search.'%'));}
        if($status){if(!in_array($status,['FORM_PENDING','FORM_CORRECTION','FORM_DECLINED','PERFORMER_PENDING','PERFORMER_DECLINED','AWAITING_PROOF','PENDING_REVIEW','REJECTED','CREATED','PENDING','FAILED','EXPIRED','PAID','PAID_REVIEW','REFUNDED'],true))throw new RuntimeException('Choose a valid payment status.');$sql.=' AND o.state=?';$params[]=$status;}
        return ['sql'=>$sql." ORDER BY CASE o.state WHEN 'FORM_PENDING' THEN 0 WHEN 'PERFORMER_PENDING' THEN 0 WHEN 'PENDING_REVIEW' THEN 0 WHEN 'PAID_REVIEW' THEN 1 WHEN 'AWAITING_PROOF' THEN 2 ELSE 3 END,o.id DESC",'params'=>$params];
    }
    if($section==='tickets'){
        $sql='SELECT t.id,t.ticket_id,t.status,t.checked_at,t.checked_by,t.participant_id,o.event_id,o.snapshot,o.environment,p.name,p.email FROM az_tickets t JOIN az_orders o ON o.id=t.order_id JOIN az_participants p ON p.id=t.participant_id WHERE o.environment=? AND ('.$scope['sql'].')';
        if($search){$sql.=' AND (t.ticket_id LIKE ? OR p.name LIKE ? OR p.email LIKE ?)';array_push($params,...array_fill(0,3,'%'.$search.'%'));}
        if($status){if(!in_array($status,['VALID','USED','BLOCKED','VOID'],true))throw new RuntimeException('Choose a valid ticket status.');$sql.=' AND t.status=?';$params[]=$status;}
        return ['sql'=>$sql.' ORDER BY t.id DESC','params'=>$params];
    }
    if($section==='submissions'){
        $scope=st_legacy_scope_sql($u,'s.event_id');$params=$scope['params'];
        $sql="SELECT s.*,e.title event_title FROM submissions s LEFT JOIN events e ON e.id=s.event_id LEFT JOIN cms_content c ON c.type='event' AND c.slug=e.slug WHERE (".$scope['sql'].')';
        if($eventId){$sql.=' AND c.id=?';$params[]=$eventId;}
        if($search){$sql.=' AND (s.name LIKE ? OR s.email LIKE ?)';array_push($params,'%'.$search.'%','%'.$search.'%');}
        return ['sql'=>$sql.' ORDER BY s.id DESC','params'=>$params];
    }
    throw new RuntimeException('Unknown operational register.');
}
function st_operation_rows(array $u,string $section,?int $eventId,string $environment,string $search='',string $status='',int $page=1,string $gameId=''): array {
    $query=st_operation_query($u,$section,$eventId,$environment,$search,$status,$gameId);
    $statement=cms_db()->prepare($query['sql'].' LIMIT 51 OFFSET '.((max(1,min(100000,$page))-1)*50));$statement->execute($query['params']);return $statement->fetchAll();
}
function st_csv_cell(mixed $value): string {
    $value=(string)$value;return preg_match('/^[\x00-\x20]*[=+@-]/u',$value)?"'".$value:$value;
}
function st_operation_export(array $u,string $section,?int $eventId,string $environment): never {
    if($u['must_change_password']||!cms_can($u,'operations','export')){http_response_code(403);exit('Export access denied.');}
    $gameId=is_string($_GET['game']??null)?$_GET['game']:'';
    $query=st_operation_query($u,$section,$eventId,$environment,'','',$gameId);$statement=cms_db()->prepare($query['sql']);$statement->execute($query['params']);
    header('Content-Type: text/csv; charset=utf-8');header('X-Content-Type-Options: nosniff');header('Content-Disposition: attachment; filename="Anazori-'.$section.'-'.$environment.'-'.date('Y-m-d').'.csv"');
    $out=fopen('php://output','w');
    $headers=match($section){'participants'=>['ID','Name','Email','Email verified','Account active','Orders in scope','Confirmed entries','Created at'],'payments'=>['Order','Event','Game','Name','Email','State','Environment','Quantity','Amount (paise)','Refunds (paise)','Payment method','Transaction reference','Payment date','Review status','Review staff ID','Review date','Review note','Receiving account snapshot','Proof ID','Registration snapshot','Registration answers','Created at'],'tickets'=>['Pass','Event','Game','Name','Email','Status','Environment','Checked in','Checked in by'],'submissions'=>['ID','Event','Name','Email','Phone','Form answers','Status','Created at']};
    fputcsv($out,$headers,',','"','');
    foreach($statement as $r){$snapshot=json_decode($r['snapshot']??'{}',true)?:[];$row=match($section){'participants'=>[$r['id'],$r['name'],$r['email'],$r['email_verified'],$r['active'],$r['orders'],$r['entries'],$r['created_at']],'payments'=>[$r['public_id'],$snapshot['title']??$r['event_slug'],$snapshot['game']??'',$r['name'],$r['email'],$r['state'],$r['environment'],$r['quantity'],$r['amount'],$r['refunded'],$r['provider'],$r['payment_reference'],$r['paid_on'],$r['review_status'],$r['reviewed_by'],$r['reviewed_at'],$r['review_note'],$r['method_snapshot'],$r['proof_id'],$r['snapshot'],$r['answers'],$r['created_at']],'tickets'=>[$r['ticket_id'],$snapshot['title']??'',$snapshot['game']??'',$r['name'],$r['email'],$r['status'],$r['environment'],$r['checked_at'],$r['checked_by']],'submissions'=>[$r['id'],$r['event_title'],$r['name'],$r['email'],$r['phone'],$r['form_data'],$r['status'],$r['created_at']]};fputcsv($out,array_map('st_csv_cell',$row),',','"','');}
    cms_audit($u,'operations.export',json_encode(['register'=>$section,'event_id'=>$eventId,'environment'=>$environment]));if($eventId)st_event_audit($u,$eventId,'operations.export',$section.' · '.$environment);exit;
}
function st_overview(array $u,?int $eventId,string $environment,array $events): void {
    $db=cms_db();$scope=st_operation_scope($u,$eventId,'o.event_id');$params=[$environment,...$scope['params']];$metrics=[];
    $participation=$eventId?az_participation_mode(cms_record($eventId)):'registration';
    $metrics[]=['Events in workspace',$eventId?1:count($events),'event','Assigned event workspaces'];
    if(cms_can($u,'participants')){$s=$db->prepare("SELECT COUNT(DISTINCT o.participant_id) FROM az_orders o WHERE o.environment=? AND ".$scope['sql']);$s->execute($params);$metrics[]=['Registered people',(int)$s->fetchColumn(),'participants','People with an order in this workspace'];}
    if($participation==='registration'&&cms_can($u,'payments')){$s=$db->prepare("SELECT COALESCE(SUM(o.amount),0) FROM az_orders o LEFT JOIN az_manual_payments m ON m.order_id=o.id WHERE o.environment=? AND o.state IN ('PAID','PAID_REVIEW','REFUNDED') AND (m.status='APPROVED' OR (o.provider<>'manual' AND o.gateway_payment IS NOT NULL AND o.gateway_payment<>'')) AND ".$scope['sql']);$s->execute($params);$metrics[]=['Confirmed collections',az_money((int)$s->fetchColumn()),'payments','Gross verified payments before refunds'];}
    if(cms_can($u,'tickets')){$s=$db->prepare('SELECT COUNT(*) FROM az_tickets t JOIN az_orders o ON o.id=t.order_id WHERE o.environment=? AND t.status=\'USED\' AND '.$scope['sql']);$s->execute($params);$metrics[]=['Checked in',(int)$s->fetchColumn(),'tickets','Passes admitted at the venue'];}
    ?>
    <div class="studio-operating-summary"><div><h2><?= $eventId?e(cms_record($eventId)['title']):'Festival control centre' ?></h2><p><?= match($participation){'ceremony'=>'Manage the opening ceremony details. No registration or participant tickets are required.','contribution'=>'Collect contribution and performance proposals. No registration tickets are issued.',default=>'Manage registrations, review payments and check tickets for your events.'} ?></p></div><span class="badge">Event records</span></div>
    <div class="metric-grid"><?php foreach($metrics as [$label,$value,$link,$note]): ?><article class="metric-card"><span><?= e($label) ?></span><strong><?= e((string)$value) ?></strong><small><?= e($note) ?></small></article><?php endforeach; ?></div>
    <?php if(!$eventId): ?><div class="workspace-grid"><?php foreach($events as $event):if($eventId&&(int)$event['id']!==$eventId)continue; ?><article class="workspace-card"><div class="panel-heading"><span class="badge"><?= e($event['status']) ?></span><span class="badge"><?= e($event['fields']['category']) ?></span></div><h2><?= e($event['title']) ?></h2><p><?= e(cms_phase_label($event['fields'])) ?></p><p class="help"><?= e($event['fields']['venue']?:'Venue to be confirmed') ?></p><div class="row-actions"><a class="primary-button" href="<?= e(st_workspace_url('overview',(int)$event['id'],$environment)) ?>">Open workspace</a></div></article><?php endforeach; ?></div><?php endif; ?>
    <?php if(!$events): ?><section class="panel empty-message"><h2>No events assigned yet</h2><p>The Super Admin can assign your event workspaces in Team access. Your account permissions remain available for shared content areas.</p></section><?php endif; ?>
    <?php if(cms_can($u,'audit')): ?><section class="panel"><div class="panel-heading"><h2>Recent event activity</h2><a class="quiet-button" href="<?= e(st_workspace_url('audit',$eventId,$environment)) ?>">All activity</a></div><?php $activity=st_event_activity_rows($u,$eventId??0,8);if(!$activity): ?><p class="empty-message">Event changes and venue check-ins will appear here.</p><?php endif;foreach($activity as $r): ?><div class="review-row"><span><strong><?= e($r['event_title']) ?></strong><small><?= e($r['action'].' · '.$r['detail']) ?></small></span><time><?= e($r['created_at']) ?></time></div><?php endforeach; ?></section><?php endif; ?>
    <?php
}
