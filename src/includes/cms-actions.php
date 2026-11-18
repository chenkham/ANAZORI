<?php
declare(strict_types=1);
function cms_handle_action(array $u): never {
 $return='/admin.php';$db=cms_db();$failed=false;
 try {
  if(!is_string($_POST['csrf_token']??null)||!csrf_verify($_POST['csrf_token']))throw new RuntimeException('Your session token expired. Reload the page and try again.');
  $action=cms_text('action',50);
  $u=st_refresh_user($u);
  if($u['must_change_password']&&$action!=='change_password')throw new RuntimeException('Set a new password in My account before making changes.');
  if(str_starts_with($action,'finance_')||$action==='reconcile_event_receipts')throw new RuntimeException('Finance management is no longer part of Studio. Use event registrations and payment reviews.');
  switch($action){
   case 'save_content':
    $type=cms_text('type',30);$schema=cms_content_schema()[$type]??null;if(!$schema)throw new InvalidArgumentException('Unknown content type.');
    $id=(int)($_POST['id']??0);$old=$id?cms_record($id):null;$return='/admin.php?section='.$type.($id?'&edit='.$id:'&new=1');
    if(($id&&!$old)||($old&&$old['type']!==$type)||!cms_can($u,$type,'edit',$old))throw new RuntimeException('You do not have access to edit this item.');
    if($type==='event'&&isset($_POST['event_setup_editor'])&&($_POST['event_editor_complete']??'')!=='1')throw new RuntimeException('The server received an incomplete event form. Increase PHP max_input_vars to 3000, reload the editor, and save again. Your saved event was not changed.');
    $title=cms_text('title',200);$slug=cms_text('slug',80);if($title==='')throw new InvalidArgumentException('A title is required.');$slug=$slug?:cms_slug($title);if(!preg_match('/^[a-z0-9]+(?:-[a-z0-9]+)*$/',$slug))throw new InvalidArgumentException('Use a URL name with lowercase letters, numbers, and hyphens.');
    if($old&&$type==='event'&&$slug!==$old['slug'])throw new InvalidArgumentException('An existing event URL cannot change; it protects registrations and shared links.');
    if($type==='event'&&!isset($_POST['registration_kind']))$_POST['registration_kind']=$old['fields']['registration_kind']??'individual';
    $fieldSchema=$type==='event'?array_diff_key($schema['fields'],array_flip(st_fixed_form_keys())):$schema['fields'];$fields=cms_validate_fields($fieldSchema);if($type==='event'){require_once __DIR__.'/commerce.php';
     if(($_POST['event_documents_editor103']??'')==='1'){$documents=json_decode($fields['event_documents'],true)?:[];$fields['rules_pdf']=$documents[0]['path']??'';}
     elseif(!array_key_exists('event_documents',$_POST)||$_POST['event_documents']==='')$fields['event_documents']=$old['fields']['event_documents']??'';
     if(!array_key_exists('rules_pdf',$_POST)&&!isset($_POST['event_documents_editor103']))$fields['rules_pdf']=$old['fields']['rules_pdf']??'';
     $fields['ticket_types']=isset($_POST['ticket_categories81'])?az_validate_prices($_POST['ticket']??[], $old['fields']['ticket_types']??'[]'):(isset($_POST['single_entry_setup'])?az_single_entry_prices($fields,$old['fields']??[],$_POST):az_validate_prices($_POST['ticket']??[], $old['fields']['ticket_types']??'[]'));
     if(isset($_POST['ticket_categories81']))$fields['ticket_categories_enabled']='1';
      $fields['payment_methods']=$old['fields']['payment_methods']??'[]';
     if($slug!=='joystick'&&!empty($_POST['games']))throw new InvalidArgumentException('Games can only be added to Joystick.');
     $fields['game_categories']=$slug==='joystick'?(isset($_POST['event_setup_editor'])?az_validate_games($_POST['games']??[]):($old['fields']['game_categories']??'[]')):'[]';
     $gameIds=array_column(az_event_games($fields,false),'id');foreach(az_prices($fields) as $pass)if(!empty($pass['game'])&&!in_array($pass['game'],$gameIds,true))throw new RuntimeException('Save your games first, then assign their passes.');
     $fields=st_preserve_event_forms($fields,$old['fields']??null);
     if(isset($_POST['form_builder_editor'])){
      foreach(['interest'=>'interest_fields','registration'=>'form_fields'] as $phase=>$key){
       $fields[$phase.'_form']=az_validate_registration_fields($_POST[$key]??[],az_event_games($fields,false));
       $fields[$phase.'_settings']=az_validate_form_settings($_POST[$phase.'_settings']??[]);
       foreach(['title','intro','button'] as $suffix)$fields[$phase.'_'.$suffix]=cms_text($phase.'_'.$suffix,$suffix==='intro'?5000:200);
      }
      $fields['form_workflow']='1';
     }
     $fields=az_participation_fields($slug,$fields);unset($fields['_event_slug']);}
    if($type==='gallery'&&$fields['image']==='')throw new InvalidArgumentException('Choose a photo from the media library.');
    if(in_array($type,['event','gallery'],true)){if($fields['category']==='')throw new InvalidArgumentException('Choose a category.');$fields['category']=cms_slug($fields['category']);if($fields['category']===''||$fields['category']==='all')throw new InvalidArgumentException('Choose a category other than all, using letters or numbers.');}
    if($type==='person'&&$fields['group']==='')throw new InvalidArgumentException('Enter a group, such as Management leads or Volunteers.');
    $status=cms_text('status',20);if(!in_array($status,['DRAFT','PUBLISHED','ARCHIVED'],true))throw new InvalidArgumentException('Choose a valid publication status.');
    if($status!=='DRAFT'&&!cms_can($u,$type,'publish',$old))throw new RuntimeException('Your role can save drafts for review, but cannot publish or archive.');
    $order=filter_var($_POST['sort_order']??0,FILTER_VALIDATE_INT);if($order===false||abs($order)>99999)throw new InvalidArgumentException('Sort order must be a whole number between -99999 and 99999.');
    $json=json_encode($fields,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);$db->beginTransaction();az_lock($db);
    $u=st_refresh_user($u);if(!cms_can($u,$type,'edit',$old)||($status!=='DRAFT'&&!cms_can($u,$type,'publish',$old)))throw new RuntimeException('Your permission to change this content was revoked.');
    if($old&&$type==='event')az_validate_ticket_history81($db,(int)$old['id'],$old['fields']['ticket_types']??'[]',$fields['ticket_types']);
    if($old&&$type==='event')foreach(az_prices($fields) as $ticket)foreach(['test','live'] as $environment)if($ticket['capacity']>0&&$ticket['capacity']<az_reserved((int)$old['id'],$ticket['id'],$environment))throw new RuntimeException('Capacity cannot be below paid passes and active reservations. Increase capacity or wait for pending reservations to expire.');
    if($old){$s=$db->prepare('UPDATE cms_content SET slug=?,title=?,data=?,status=?,sort_order=?,revision=revision+1,updated_at=? WHERE id=? AND revision=?');$s->execute([$slug,$title,$json,$status,$order,gmdate('c'),$id,(int)($_POST['revision']??0)]);if(!$s->rowCount())throw new RuntimeException('Someone else edited this item. Reload to review their changes before saving.');}
    else{$s=$db->prepare('INSERT INTO cms_content(type,slug,title,data,status,sort_order,created_by,updated_at) VALUES(?,?,?,?,?,?,?,?)');$s->execute([$type,$slug,$title,$json,$status,$order,$u['id'],gmdate('c')]);$id=(int)$db->lastInsertId();}
    if($type==='event'){cms_sync_event($slug,$title,$fields,$status);st_event_audit($u,$id,'event.save',$title.' · '.$status);}
    cms_audit($u,$type.'.save',$title.' · '.$status);$db->commit();cms_flash($status==='DRAFT'?'Draft saved. An editor or administrator can review and publish it.':'Saved. The website now reflects this publication status.');$return='/admin.php?section='.$type.'&edit='.$id;break;
   case 'delete_content':
    $old=cms_record((int)($_POST['id']??0));if(!$old||!cms_can($u,$old['type'],'delete',$old))throw new RuntimeException('You cannot remove this item.');$return='/admin.php?section='.$old['type'];
    if((int)($_POST['revision']??0)!==(int)$old['revision'])throw new RuntimeException('This item changed. Reload before removing it.');
    $db->beginTransaction();az_lock($db);$u=st_refresh_user($u);if(!cms_can($u,$old['type'],'delete',$old))throw new RuntimeException('Your permission to remove this item was revoked.');
    if($old['type']==='event'){
     foreach(['az_orders','st_budgets','st_expenses','st_finance_ledger','st_closeouts'] as $table){$check=$db->prepare('SELECT COUNT(*) FROM '.$table.' WHERE event_id=?');$check->execute([$old['id']]);if($check->fetchColumn())throw new RuntimeException('This event has operational or financial history. Archive it instead to preserve its records.');}
     $check=$db->prepare('SELECT COUNT(*) FROM submissions s JOIN events e ON e.id=s.event_id WHERE e.slug=?');$check->execute([$old['slug']]);if($check->fetchColumn())throw new RuntimeException('This event has submissions. Archive it to keep its event workspace and history.');
     st_event_audit($u,(int)$old['id'],'event.delete',$old['title']);
    }
    $s=$db->prepare('DELETE FROM cms_content WHERE id=? AND revision=?');$s->execute([$old['id'],$old['revision']]);if(!$s->rowCount())throw new RuntimeException('This item changed. Reload before removing it.');
    if($old['type']==='event'){$s=$db->prepare("UPDATE events SET status='COMPLETED' WHERE slug=?");$s->execute([$old['slug']]);}cms_audit($u,$old['type'].'.delete',$old['title']);$db->commit();cms_flash('Removed from the website. Existing submission records are retained.');break;
   case 'save_settings':
    $return='/admin.php?section=settings';if(!cms_can($u,'settings','edit'))throw new RuntimeException('Only administrators can change website settings.');
    $group=cms_text('group',100);$schema=cms_setting_schema()[$group]??null;if(!$schema)throw new InvalidArgumentException('Unknown settings group.');$data=cms_validate_fields($schema);
    if(isset($data['year'])&&!preg_match('/^20\d{2}$/',$data['year']))throw new InvalidArgumentException('Edition must be a four-digit year.');
    foreach(['site_name','logo','hero_video','email','sponsor_email'] as $key)if(array_key_exists($key,$data)&&$data[$key]==='')throw new InvalidArgumentException(str_replace('_',' ',$key).' is required.');
    $db->beginTransaction();az_lock($db);$u=st_refresh_user($u);if(!cms_can($u,'settings','edit'))throw new RuntimeException('Your permission to change website settings was revoked.');$version=(int)($_POST['revision']??0);$s=$db->prepare("UPDATE cms_settings SET value=? WHERE setting_key='settings_revision' AND value=?");$s->execute([(string)($version+1),(string)$version]);if(!$s->rowCount())throw new RuntimeException('Settings changed in another session. Reload before saving.');
    $s=$db->query("SELECT value FROM cms_settings WHERE setting_key='site'");$all=json_decode($s->fetchColumn(),true)?:[];cms_put_setting('site',json_encode(array_replace($all,$data),JSON_UNESCAPED_UNICODE));cms_audit($u,'settings.save',$group);$db->commit();cms_flash($group.' updated.');$return.='&environment='.(($_POST['studio_environment']??'live')==='test'?'test':'live').'#group-'.cms_slug($group);break;
   case 'upload_media':
    $return='/admin.php?section=media';cms_upload($u,$_FILES['file']??[]);cms_flash('Uploaded. You can now choose this file in any content editor.');break;
   case 'remove_media':
    $return='/admin.php?section=media';if(!cms_can($u,'media','delete'))throw new RuntimeException('You cannot remove media.');$id=(int)($_POST['id']??0);$db->beginTransaction();az_lock($db);$u=st_refresh_user($u);if(!cms_can($u,'media','delete'))throw new RuntimeException('Your permission to remove media was revoked.');$s=$db->prepare('SELECT * FROM cms_media WHERE id=?');$s->execute([$id]);$m=$s->fetch();if(!$m)throw new InvalidArgumentException('File not found.');
    $used=false;foreach($db->query('SELECT data FROM cms_content') as $r)if(str_contains($r['data'],$m['path'])||str_contains($r['data'],str_replace('/','\/',$m['path'])))$used=true;
    foreach($db->query("SELECT value FROM cms_settings WHERE setting_key='site'") as $r)if(str_contains($r['value'],$m['path'])||str_contains($r['value'],str_replace('/','\/',$m['path'])))$used=true;
    if($used)throw new InvalidArgumentException('This file is still used by content or settings. Replace those references first.');$s=$db->prepare('DELETE FROM cms_media WHERE id=?');$s->execute([$id]);cms_audit($u,'media.remove',$m['title']);$db->commit();cms_flash('Removed from the media library.');break;
   case 'save_user':
    $return='/admin.php?section=users';if(!az_is_super($u))throw new RuntimeException('Only the master Super Admin can manage staff access.');
    $id=(int)($_POST['id']??0);$old=null;if($id){$q=$db->prepare('SELECT * FROM users WHERE id=?');$q->execute([$id]);$old=$q->fetch();if(!$old)throw new RuntimeException('Account not found.');}
    if($old&&az_is_super($old))throw new RuntimeException('The master account is fixed. Change its password in My account.');
    $role=cms_text('role',30);if(!in_array($role,['ADMIN','FACULTY','COORDINATOR','EDITOR','VOLUNTEER'],true))throw new RuntimeException('Choose a valid staff role.');
    $username=strtolower(cms_text('username',100));if(!preg_match('/^[a-z0-9._-]{3,60}$/',$username))throw new RuntimeException('Use a username of 3–60 letters, digits, dots, underscores or hyphens.');
    $email=strtolower(cms_text('email',254));if(!filter_var($email,FILTER_VALIDATE_EMAIL)||$email===ANAZORI_SUPER_EMAIL||$username===ANAZORI_SUPER_EMAIL)throw new RuntimeException('Use a valid staff email other than the master address.');
    $q=$db->prepare('SELECT id FROM users WHERE LOWER(email)=? AND id<>?');$q->execute([$email,$id]);if($q->fetch())throw new RuntimeException('That email already has staff access.');
    $name=cms_text('display_name',150);$title=cms_text('staff_title',100);$active=isset($_POST['active'])?1:0;$password=$_POST['password']??'';if(!is_string($password))throw new RuntimeException('Invalid password.');if(!$old||$password!=='')az_password($password);
    $p=$_POST['permissions']??[];if(!is_array($p)||array_filter($p,fn($v)=>!is_string($v)))throw new RuntimeException('Invalid permissions.');$p=array_values(array_intersect(array_keys(az_permission_labels()),$p));
    foreach($p as $permission){[$module,$operation]=explode('.',$permission);if($operation!=='view'&&isset(az_permission_labels()[$module.'.view']))$p[]=$module.'.view';}if(in_array('tickets.scan',$p,true)&&!in_array('tickets.view',$_POST['permissions']??[],true))$p=array_values(array_diff($p,['tickets.view']));$p=array_values(array_unique(array_merge($p,$role==='COORDINATOR'?st_coordinator_permissions():[])));
    $hash=$password!==''?password_hash($password,PASSWORD_DEFAULT):($old['password_hash']??'');$db->beginTransaction();az_lock($db);$u=st_refresh_user($u);if(!az_is_super($u))throw new RuntimeException('Only the master Super Admin can manage staff access.');
    if($id){$q=$db->prepare('SELECT * FROM users WHERE id=?');$q->execute([$id]);$old=$q->fetch();if(!$old||az_is_super($old))throw new RuntimeException('Choose a staff account other than the fixed master account.');if($password==='')$hash=$old['password_hash'];}
    $q=$db->prepare('SELECT id FROM users WHERE LOWER(email)=? AND id<>?');$q->execute([$email,$id]);if($q->fetch())throw new RuntimeException('That email already has staff access.');
    if($old)$db->prepare('UPDATE users SET username=?,display_name=?,email=?,role=?,active=?,staff_title=?,permissions=?,password_hash=?,must_change_password=?,session_version=session_version+1 WHERE id=?')->execute([$username,$name,$email,$role,$active,$title,json_encode($p),$hash,$password!==''?1:$old['must_change_password'],$id]);
    else $db->prepare('INSERT INTO users(username,display_name,email,role,active,staff_title,permissions,password_hash,must_change_password) VALUES(?,?,?,?,?,?,?,?,1)')->execute([$username,$name,$email,$role,$active,$title,json_encode($p),$hash]);
    if(!$old)$id=(int)$db->lastInsertId();
    if(!$old||isset($_POST['event_scope_present'])){ $eventIds=$_POST['event_ids']??[];if(!is_array($eventIds))throw new RuntimeException('Choose valid event assignments.');st_set_assignments($u,$id,$eventIds,($_POST['event_scope']??'assigned')==='all'); }
    cms_audit($u,'account.save',$username.' · '.$role.' · permissions '.implode(', ',$p));$db->commit();cms_flash('Staff access saved. Older sessions are revoked; temporary passwords must be changed.');break;
   case 'save_integrations':
    $return='/admin.php?section=integrations';if(!az_is_super($u))throw new RuntimeException('Only the master Super Admin can configure integrations.');$db->beginTransaction();az_lock($db);$u=st_refresh_user($u);if(!az_is_super($u))throw new RuntimeException('Only the master Super Admin can configure integrations.');az_save_integrations();cms_audit($u,'integrations.save','Provider configuration updated (secrets omitted)');$db->commit();cms_flash('Integration settings saved.');break;
   case 'participant_status':
    $return='/admin.php?section=participants';$db->beginTransaction();az_lock($db);$u=st_refresh_user($u);if(!cms_can($u,'participants','edit'))throw new RuntimeException('No participant management access.');st_require_participant($u,(int)($_POST['id']??0),true);$db->prepare('UPDATE az_participants SET active=?,session_version=session_version+1 WHERE id=?')->execute([isset($_POST['active'])?1:0,(int)($_POST['id']??0)]);cms_audit($u,'participant.status','Participant '.(int)($_POST['id']??0));$db->commit();cms_flash('Participant access updated. Issued tickets retain their individual status.');break;
   case 'verify_payment':
      $return='/admin.php?section=payments';if(!cms_can($u,'payments','verify'))throw new RuntimeException('No payment verification access.');require_once __DIR__.'/commerce.php';$order=st_require_order($u,(int)($_POST['id']??0));az_refresh_order($order,$u);st_event_audit($u,(int)$order['event_id'],'payment.verify',$order['public_id']);cms_audit($u,'payment.verify',$order['public_id']);cms_flash('Gateway status checked. Tickets are issued only for verified completed payments.');break;
   case 'review_manual_payment':
    $return='/admin.php?section=payments';require_once __DIR__.'/commerce.php';$reviewed=az_review_manual_payment($u,(int)($_POST['id']??0),cms_text('decision',20),$_POST);cms_flash($reviewed['state']==='PAID_REVIEW'?'Payment confirmed. Increase event capacity or record an actual refund before releasing passes.':'Payment review saved.');break;
   case 'review_performer':
    require_once __DIR__.'/commerce.php';$reviewed=az_review_performer($u,(int)($_POST['id']??0),cms_text('decision',20));$return='/admin.php?section=payments&event_id='.(int)$reviewed['event_id'];cms_flash($reviewed['state']==='PAID'?'Performer confirmed. Their free ticket is now available in their account.':'Performer application declined.');break;
   case 'review_form_response':
    require_once __DIR__.'/commerce.php';$reviewed=az_review_form_order($u,(int)($_POST['id']??0),cms_text('decision',20),$_POST);$return='/admin.php?section=payments&event_id='.(int)$reviewed['event_id'];cms_flash($reviewed['state']==='PAID'?'Response approved. The ticket is available in the participant account.':($reviewed['state']==='PAID_REVIEW'?'Payment confirmed; increase pass capacity before issuing the ticket.':'Review saved. The participant can see your note.'));break;
   case 'block_ticket':
   case 'unblock_ticket':
    $return='/admin.php?section=tickets';require_once __DIR__.'/commerce.php';az_block_ticket($u,(int)($_POST['id']??0),$action==='block_ticket',cms_text('reason',1000));cms_flash('Ticket status updated.');break;
   case 'record_manual_refund':
    $return='/admin.php?section=payments';require_once __DIR__.'/commerce.php';az_record_manual_refund($u,(int)($_POST['id']??0),$_POST);cms_flash('Completed refund recorded.');break;
   case 'reconcile_event_receipts':
    $return='/admin.php?section=reports&event_id='.(int)($_POST['event_id']??0);az_reconcile_event_receipts($u,(int)($_POST['event_id']??0),$_POST);cms_flash('Event account comparison saved.');break;
   case 'revoke_ticket':
    $return='/admin.php?section=tickets';$db->beginTransaction();az_lock($db);$u=st_refresh_user($u);if(!cms_can($u,'tickets','revoke'))throw new RuntimeException('No ticket revocation access.');$id=(int)($_POST['id']??0);$ticket=st_require_ticket($u,$id);$db->prepare("UPDATE az_tickets SET status='VOID' WHERE id=?")->execute([$id]);st_event_audit($u,(int)$ticket['order_event_id'],'ticket.revoke',$ticket['ticket_id']);cms_audit($u,'ticket.revoke','Ticket '.$id);$db->commit();cms_flash('Ticket revoked. It can no longer be checked in.');break;
   case 'save_certificate_awards':
    $eventId=filter_var($_POST['event_id']??0,FILTER_VALIDATE_INT);if($eventId===false||$eventId<1)throw new InvalidArgumentException('Choose an event.');$return='/admin.php?section=certificates&event_id='.$eventId;
    $rows=$_POST['awards']??[];if(!is_array($rows)||count($rows)>12)throw new InvalidArgumentException('Use up to 12 podium teams.');$clean=[];$seen=[];
    foreach($rows as $row){if(!is_array($row))throw new InvalidArgumentException('Check the podium list.');$team=trim((string)($row['team_name']??''));if($team==='')continue;if(mb_strlen($team)>120||preg_match('/[\x00-\x1F]/u',$team))throw new InvalidArgumentException('Check each team name.');$place=filter_var($row['place']??null,FILTER_VALIDATE_INT);if($place===false||!in_array($place,[1,2,3],true))throw new InvalidArgumentException('Choose 1st, 2nd or 3rd place for each team.');$key=az_certificate_team_key($team);if(isset($seen[$key]))throw new InvalidArgumentException('Each team can appear once in the podium list.');$seen[$key]=true;$clean[]=[$key,$team,$place];}
    $db->beginTransaction();az_lock($db);$u=az_certificate_require_manage($u,(int)$eventId);$db->prepare('DELETE FROM az_certificate_awards WHERE event_id=?')->execute([(int)$eventId]);$save=$db->prepare('INSERT INTO az_certificate_awards(event_id,team_key,team_name,place,updated_by,updated_at) VALUES(?,?,?,?,?,?)');foreach($clean as [$key,$team,$place])$save->execute([(int)$eventId,$key,$team,$place,(int)$u['id'],gmdate('c')]);st_event_audit($u,(int)$eventId,'certificate.results.save',count($clean).' podium teams');cms_audit($u,'certificate.results.save','Event '.$eventId.' · '.count($clean).' teams');$db->commit();cms_flash('Podium results saved. Existing certificates now show the updated participant or winner status.');break;
   case 'issue_certificate':
    $eventId=filter_var($_POST['event_id']??0,FILTER_VALIDATE_INT);if($eventId===false||$eventId<1)throw new InvalidArgumentException('Choose an event.');$return='/admin.php?section=certificates&event_id='.$eventId;$publicId=az_certificate_issue_order($u,(int)$eventId,(int)($_POST['order_id']??0),cms_text('recipient_email',254),cms_text('recipient_name',150),cms_text('institution',180));cms_flash('Certificate issued: '.$publicId.'. The participant can download it from My festival.');break;
   case 'issue_team_certificates':
    $eventId=filter_var($_POST['event_id']??0,FILTER_VALIDATE_INT);if($eventId===false||$eventId<1)throw new InvalidArgumentException('Choose an event.');$return='/admin.php?section=certificates&event_id='.$eventId;$issued=az_certificate_issue_team_members($u,(int)$eventId,(int)($_POST['order_id']??0));cms_flash(count($issued).' certificate'.(count($issued)===1?'':'s').' issued or refreshed in the team leader’s My festival dashboard.');break;
   case 'revoke_certificate':
   case 'restore_certificate':
    $eventId=filter_var($_POST['event_id']??0,FILTER_VALIDATE_INT);if($eventId===false||$eventId<1)throw new InvalidArgumentException('Choose an event.');$return='/admin.php?section=certificates&event_id='.$eventId;az_certificate_set_status($u,(int)($_POST['certificate_row_id']??0),$action==='restore_certificate');cms_flash($action==='restore_certificate'?'Certificate restored.':'Certificate revoked. Its verification link will show that it is no longer valid.');break;
   case 'change_password':
    $return='/admin.php?section=profile';$current=$_POST['current_password']??'';$password=$_POST['password']??'';$confirm=$_POST['confirm_password']??'';
    if(!is_string($current)||!is_string($password)||$password!==$confirm||strlen($password)<12||strlen($password)>200)throw new InvalidArgumentException('Use matching passwords of 12–200 characters.');
    if(!rate_limit_check('password_change',5,300))throw new RuntimeException('Too many attempts. Please wait five minutes.');
    $s=$db->prepare('SELECT password_hash FROM users WHERE id=?');$s->execute([$u['id']]);$hash=$s->fetchColumn();if(!password_verify($current,$hash))throw new InvalidArgumentException('Your current password is incorrect.');
    if(password_verify($password,$hash)||$password===DEFAULT_ADMIN_PASS)throw new InvalidArgumentException('Choose a new password.');
    $newHash=password_hash($password,PASSWORD_DEFAULT);$db->beginTransaction();az_lock($db);$u=st_refresh_user($u);$s=$db->prepare('SELECT password_hash FROM users WHERE id=?');$s->execute([$u['id']]);$latestHash=$s->fetchColumn();if(!is_string($latestHash)||!hash_equals($hash,$latestHash))throw new RuntimeException('Your account password changed. Sign in again before changing it.');
    $s=$db->prepare('UPDATE users SET password_hash=?,must_change_password=0,session_version=session_version+1 WHERE id=?');$s->execute([$newHash,$u['id']]);cms_audit($u,'account.password','Changed own password');$db->commit();$_SESSION['admin_version']=(int)$u['session_version']+1;session_regenerate_id(true);cms_flash('Password updated. You can now manage your assigned areas.');break;
   case 'delete_demo_record108':
    $return='/admin.php?section=cleanup';require_once __DIR__.'/demo-cleanup108.php';az_delete_demo108($u,cms_text('kind',20),(int)($_POST['id']??0),cms_text('confirmation',80));cms_flash('Selected demo record and linked registration data deleted.');break;
   case 'submission_status':
    $return='/admin.php?section=submissions';$db->beginTransaction();az_lock($db);$u=st_refresh_user($u);if(!cms_can($u,'submissions','edit'))throw new RuntimeException('You do not have participant-data access.');$status=cms_text('status',20);if(!in_array($status,['RECEIVED','PENDING','CONTACTED','CONFIRMED','REJECTED','ARCHIVED'],true))throw new InvalidArgumentException('Invalid status.');$s=$db->prepare('SELECT event_id,form_data FROM submissions WHERE id=?');$s->execute([(int)($_POST['id']??0)]);$submission=$s->fetch();if(!$submission)throw new RuntimeException('Submission unavailable.');if((json_decode($submission['form_data'],true)['type']??'')==='INTEREST')throw new RuntimeException('Interest responses are collected only and do not need approval.');if((json_decode($submission['form_data'],true)['type']??'')==='CONTRIBUTION'&&!in_array($status,['RECEIVED','CONTACTED','ARCHIVED'],true))throw new RuntimeException('Use a contribution tracking status.');$legacyId=(int)$submission['event_id'];st_require_legacy_event($u,$legacyId);$s=$db->prepare('UPDATE submissions SET status=? WHERE id=?');$s->execute([$status,(int)($_POST['id']??0)]);$cmsId=st_legacy_cms_id($legacyId);if($cmsId)st_event_audit($u,$cmsId,'submission.status','Submission '.(int)$_POST['id'].' · '.$status);cms_audit($u,'submission.status','Submission '.(int)($_POST['id']??0).' · '.$status);$db->commit();cms_flash('Submission status updated.');break;
   default:throw new InvalidArgumentException('Unknown action.');
  }
 }catch(Throwable $error){$failed=true;if($db->inTransaction())$db->rollBack();$message=$error instanceof PDOException?'This change could not be saved. Check that the URL name or username is not already in use.':$error->getMessage();cms_flash($message,'error');}
 if(($_POST['response_format']??'')==='json'&&($_POST['action']??'')==='save_content'){
    header('Content-Type: application/json');header('Cache-Control: no-store');if($failed)http_response_code(400);
    echo json_encode(['ok'=>!$failed,'error'=>$failed?($_SESSION['cms_flash']['message']??'Save failed.'):'','revision'=>!$failed?(cms_record((int)$id)['revision']??0):0]);unset($_SESSION['cms_flash']);exit;
 }
 if(str_starts_with($return,'/admin.php')){
  $parts=explode('#',$return,2);$return=$parts[0];
  if(isset($_POST['studio_event_id'])&&(int)$_POST['studio_event_id']>0&&!str_contains($return,'event_id='))$return.=(str_contains($return,'?')?'&':'?').'event_id='.(int)$_POST['studio_event_id'];
  if(!str_contains($return,'environment='))$return.=(str_contains($return,'?')?'&':'?').'environment='.(($_POST['studio_environment']??'live')==='test'?'test':'live');
  if(isset($parts[1]))$return.='#'.$parts[1];
 }
 header('Location: '.$return, true,303);exit;
}
function cms_sync_event(string $slug,string $title,array $fields,string $status): void {
 $db=cms_db();$s=$db->prepare('SELECT id FROM events WHERE slug=?');$s->execute([$slug]);$id=$s->fetchColumn();$state=$status==='PUBLISHED'&&in_array(cms_event_phase($fields),['interest','open','none'],true)?'ACTIVE':'COMPLETED';
 if($id){$s=$db->prepare('UPDATE events SET title=?,status=? WHERE id=?');$s->execute([$title,$state,$id]);}else{$s=$db->prepare('INSERT INTO events(slug,title,description,status) VALUES(?,?,?,?)');$s->execute([$slug,$title,$fields['description']??'',$state]);}
}
