<?php
declare(strict_types=1);

function az_cleanup_owner108(array $actor): array {
    $actor=st_refresh_user($actor);
    if($actor['must_change_password']||!az_is_super($actor))throw new RuntimeException('Only the Super Admin can delete demo records.');
    return $actor;
}

function az_cleanup_files108(PDO $db,string $column,int $id,array &$files): void {
    if(!in_array($column,['order_id','submission_id','participant_id'],true))throw new LogicException('Invalid cleanup scope.');
    $query=$db->prepare('SELECT id,filename FROM az_registration_files WHERE '.$column.'=?');$query->execute([$id]);
    foreach($query->fetchAll() as $file){$files[]=[az_form_file_directory(),$file['filename']];$db->prepare('DELETE FROM az_draft_files WHERE file_id=?')->execute([$file['id']]);}
    $db->prepare('DELETE FROM az_registration_files WHERE '.$column.'=?')->execute([$id]);
}

function az_cleanup_order108(PDO $db,array $order,array &$files): void {
    $check=$db->prepare('SELECT 1 FROM st_settlement_orders WHERE order_id=?');$check->execute([$order['id']]);
    if($check->fetchColumn())throw new RuntimeException('This registration belongs to a recorded settlement. Keep its financial history; it is not available for demo cleanup.');
    $tickets=$db->prepare('SELECT id FROM az_tickets WHERE order_id=?');$tickets->execute([$order['id']]);
    foreach($tickets->fetchAll(PDO::FETCH_COLUMN) as $id)foreach(['az_checkins','az_ticket_blocks'] as $table)$db->prepare('DELETE FROM '.$table.' WHERE ticket_id=?')->execute([$id]);
    $proofs=$db->prepare('SELECT filename FROM az_payment_proofs WHERE order_id=?');$proofs->execute([$order['id']]);foreach($proofs->fetchAll(PDO::FETCH_COLUMN) as $name)$files[]=[az_proof_directory(),$name];
    az_cleanup_files108($db,'order_id',(int)$order['id'],$files);
    foreach(['az_tickets','az_mail_jobs89','az_form_reviews','az_form_payment_refs','az_form_responses','az_payment_reviews','az_payment_proofs','az_manual_payments','az_refunds'] as $table)$db->prepare('DELETE FROM '.$table.' WHERE order_id=?')->execute([$order['id']]);
    $game=json_decode($order['snapshot'],true)['game_id']??'';
    foreach([az_draft_context81($game),(int)$order['id']] as $context){
        $drafts=az_checkout_draft_files((int)$order['participant_id'],(int)$order['event_id'],$context);
        foreach($drafts as $file){$files[]=[az_form_file_directory(),$file['filename']];$db->prepare('DELETE FROM az_draft_files WHERE file_id=?')->execute([$file['id']]);$db->prepare('DELETE FROM az_registration_files WHERE id=?')->execute([$file['id']]);}
        $db->prepare('DELETE FROM az_checkout_drafts WHERE participant_id=? AND event_id=? AND context_id=?')->execute([$order['participant_id'],$order['event_id'],$context]);
    }
    $db->prepare('DELETE FROM az_orders WHERE id=?')->execute([$order['id']]);
}

function az_cleanup_submission108(PDO $db,int $id,array &$files): void {
    az_cleanup_files108($db,'submission_id',$id,$files);$db->prepare('DELETE FROM submissions WHERE id=?')->execute([$id]);
}

/** An explicit record and typed identity are required; never infer which entries are demos. */
function az_delete_demo108(array $actor,string $kind,int $id,string $confirmation): void {
    if(!in_array($kind,['registration','ticket','submission','participant'],true)||$id<1)throw new InvalidArgumentException('Choose one record to delete.');
    $db=cms_db();$files=[];$db->beginTransaction();
    try{
        az_lock($db);$actor=az_cleanup_owner108($actor);
        if($kind==='ticket'){$query=$db->prepare('SELECT * FROM az_tickets WHERE id=?');$query->execute([$id]);$ticket=$query->fetch();if(!$ticket)throw new RuntimeException('Ticket unavailable.');$identity=$ticket['ticket_id'];$order=az_order((int)$ticket['order_id']);}
        elseif($kind==='registration'){$order=az_order($id);$identity=$order['public_id']??'';}
        else{$table=$kind==='participant'?'az_participants':'submissions';$query=$db->prepare('SELECT * FROM '.$table.' WHERE id=?');$query->execute([$id]);$record=$query->fetch();$identity=$record?strtoupper($kind).'-'.$id:'';}
        if($identity===''||!hash_equals($identity,trim($confirmation)))throw new RuntimeException('Type the exact displayed reference to confirm deletion.');
        if($kind==='registration'||$kind==='ticket')az_cleanup_order108($db,$order,$files);
        elseif($kind==='submission')az_cleanup_submission108($db,$id,$files);
        else{
            $orders=$db->prepare('SELECT * FROM az_orders WHERE participant_id=?');$orders->execute([$id]);foreach($orders->fetchAll() as $order)az_cleanup_order108($db,$order,$files);
            $submissions=$db->prepare('SELECT id FROM submissions WHERE LOWER(email)=?');$submissions->execute([strtolower($record['email'])]);foreach($submissions->fetchAll(PDO::FETCH_COLUMN) as $submission)az_cleanup_submission108($db,(int)$submission,$files);
            az_cleanup_files108($db,'participant_id',$id,$files);
            foreach(['az_draft_files','az_checkout_drafts','az_remember_tokens102','az_mail_jobs89'] as $table)$db->prepare('DELETE FROM '.$table.' WHERE participant_id=?')->execute([$id]);
            foreach(['az_challenges','az_auth_events'] as $table)$db->prepare("DELETE FROM $table WHERE user_kind='participant' AND user_id=?")->execute([$id]);
            $db->prepare('DELETE FROM az_participants WHERE id=?')->execute([$id]);
        }
        foreach($files as [$directory,$name])if(!is_string($name)||!preg_match('/^[a-f0-9]{48}\.[a-z0-9]{2,5}$/D',$name))throw new RuntimeException('A private filename needs administrator review before cleanup.');
        cms_audit($actor,'demo.delete',$kind.' '.$identity);$db->commit();
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
    foreach($files as [$directory,$name]){
        $base=realpath($directory);$file=$directory.DIRECTORY_SEPARATOR.$name;$resolved=realpath($file);
        if(!$resolved)continue;
        if(!$base||is_link($file)||!str_starts_with(strtolower(str_replace('\\','/',$resolved)),strtolower(str_replace('\\','/',$base)).'/')||!@unlink($file))error_log('ANAZORI demo cleanup: private file needs manual review.');
    }
}

function st_demo_cleanup108(array $actor): void {
    az_cleanup_owner108($actor);$kind=is_string($_GET['kind']??null)?$_GET['kind']:'registration';
    if(!in_array($kind,['registration','ticket','submission','participant'],true))$kind='registration';
    $search=is_string($_GET['q']??null)?mb_substr(trim($_GET['q']),0,100):'';$db=cms_db();
    $queries=[
        'registration'=>"SELECT o.id,o.public_id AS reference,p.name,p.email,o.state AS status FROM az_orders o JOIN az_participants p ON p.id=o.participant_id",
        'ticket'=>"SELECT t.id,t.ticket_id AS reference,p.name,p.email,t.status FROM az_tickets t JOIN az_participants p ON p.id=t.participant_id",
        'submission'=>"SELECT id,name,email,status FROM submissions",
        'participant'=>"SELECT id,name,email,CASE WHEN active=1 THEN 'ACTIVE' ELSE 'DISABLED' END AS status FROM az_participants",
    ];
    $sql=$queries[$kind];$params=[];
    if($search!==''){$sql.=' WHERE '.($kind==='registration'?'o.public_id LIKE ? OR p.name LIKE ? OR p.email LIKE ?':($kind==='ticket'?'t.ticket_id LIKE ? OR p.name LIKE ? OR p.email LIKE ?':'name LIKE ? OR email LIKE ?'));$params=array_fill(0,in_array($kind,['registration','ticket'],true)?3:2,'%'.$search.'%');}
    $sql.=' ORDER BY '.($kind==='registration'?'o.id':($kind==='ticket'?'t.id':'id')).' DESC LIMIT 50';$query=$db->prepare($sql);$query->execute($params);
    echo '<section class="panel"><h2>Demo cleanup</h2><p class="help">Choose test records explicitly. Deletion is permanent. A ticket deletion also deletes its registration, payment evidence and pending mail, allowing a fresh registration. Deleting a participant also removes their registrations, drafts and submissions. Staff, events, form setup and shared media remain. No bank payment is refunded by deleting data.</p><form method="get" class="list-toolbar"><input type="hidden" name="section" value="cleanup"><label>Record type<select name="kind">';
    foreach(['registration'=>'Registrations and linked tickets','ticket'=>'Tickets and linked registration','submission'=>'Interest / contribution submissions','participant'=>'Participant accounts and all their entries'] as $value=>$label)echo '<option value="'.$value.'"'.($kind===$value?' selected':'').'>'.$label.'</option>';
    echo '</select></label><label>Find demo records<input name="q" value="'.e($search).'" placeholder="Name, email or reference"></label><button class="quiet-button">Search</button></form><div class="operation-list">';
    foreach($query->fetchAll() as $row){$identity=$row['reference']??strtoupper($kind).'-'.$row['id'];echo '<details class="operation-row"><summary><strong>'.e($row['name']).'</strong><span>'.e($identity).' · '.e($row['status']).'</span></summary><div class="disclosure-content"><p>'.e($row['email']).'</p><form method="post" data-confirm="Permanently delete this selected record and its linked registration data?">';cms_hidden('delete_demo_record108');echo '<input type="hidden" name="kind" value="'.$kind.'"><input type="hidden" name="id" value="'.(int)$row['id'].'"><label class="field"><span>Type '.e($identity).' to confirm</span><input name="confirmation" required autocomplete="off"></label><button class="danger-button" type="submit">Permanently delete selected demo record</button></form></div></details>';}
    echo '</div></section>';
}
