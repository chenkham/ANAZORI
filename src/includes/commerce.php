<?php
declare(strict_types=1);
require_once __DIR__.'/cms.php';
require_once __DIR__.'/phonepe.php';
require_once __DIR__.'/payment-view.php';
function az_inr_to_paise(string $price): int {
 if(!preg_match('/^\d{1,6}(?:\.\d{1,2})?$/',$price))throw new RuntimeException('Enter a valid INR fee with up to two decimal places.');
 $parts=explode('.',$price);$paise=(int)$parts[0]*100+(int)str_pad($parts[1]??'',2,'0');
 if($paise>0&&$paise<100)throw new RuntimeException('Use ₹0 for free entry or at least ₹1 for paid registration.');return $paise;
}
function az_prices(array $fields): array {
 if(az_participation_mode($fields)==='contribution')return [];
 if(az_participation_mode($fields)==='ceremony')return [];
 if(az_participation_mode($fields)==='performers')return [['id'=>'performer-pass','label'=>'Performer ticket','price'=>0,'capacity'=>0,'active'=>true]];
 $types=json_decode($fields['ticket_types']??'[]',true)?:[];
 if($types||($fields['ticket_categories_enabled']??'')==='1')return $types;
 if(!array_key_exists('registration_fee',$fields))return [];
 return [['id'=>'standard-entry','label'=>'Event entry','price'=>az_inr_to_paise((string)$fields['registration_fee']),'capacity'=>0,'active'=>true]];
}
function az_validate_prices(mixed $rows,string $previous='[]'): string {
 if(!is_array($rows)||count($rows)>20)throw new RuntimeException('Use up to 20 ticket types.');$out=[];$ids=[];
 foreach($rows as $row){if(!is_array($row))throw new RuntimeException('Invalid ticket type.');$label=trim((string)($row['label']??''));if($label==='')continue;if(mb_strlen($label)>80)throw new RuntimeException('Ticket names must be under 80 characters.');
  $id=$row['id']??'';if(!is_string($id)||($id&&!preg_match('/^[a-z0-9-]{3,60}$/',$id)))throw new RuntimeException('Invalid ticket identity.');$id=$id?:'type-'.bin2hex(random_bytes(6));if(in_array($id,$ids,true))throw new RuntimeException('Duplicate ticket type.');$ids[]=$id;
  $price=(string)($row['price']??'');$capacity=(string)($row['capacity']??'0');if(!preg_match('/^\d{1,6}(?:\.\d{1,2})?$/',$price)||!ctype_digit($capacity)||(int)$capacity>1000000)throw new RuntimeException('Enter a valid INR price and capacity (0 means unlimited).');
  $paise=az_inr_to_paise($price);$game=az_setup_text($row,'game',60);if($game!==''&&!preg_match('/^[a-z0-9-]{3,60}$/D',$game))throw new RuntimeException('Choose a valid game for this pass.');
  $people=filter_var($row['people']??1,FILTER_VALIDATE_INT);if($people===false||$people<1||$people>1000)throw new InvalidArgumentException('One ticket may cover 1 to 1000 people.');
  $out[]=['id'=>$id,'game'=>$game,'label'=>$label,'description'=>az_setup_text($row,'description',500),'people'=>$people,'price'=>$paise,'capacity'=>(int)$capacity,'active'=>isset($row['active'])];
 }
 return json_encode($out,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
}
function az_event(string $slug): ?array {$slug=$slug==='prativa'?'youth-parliament':$slug;$s=cms_db()->prepare("SELECT * FROM cms_content WHERE type='event' AND slug=? AND status='PUBLISHED'");$s->execute([$slug]);$r=$s->fetch();return $r?cms_unpack($r):null;}
function az_order(int $id): ?array {$s=cms_db()->prepare('SELECT * FROM az_orders WHERE id=?');$s->execute([$id]);return $s->fetch()?:null;}
function az_order_public(string $id): ?array {$s=cms_db()->prepare('SELECT * FROM az_orders WHERE public_id=?');$s->execute([$id]);return $s->fetch()?:null;}
function az_reserved(int $event,string $type,string $environment,int $except=0): int {
 $s=cms_db()->prepare("SELECT COALESCE(SUM(quantity),0) FROM az_orders WHERE event_id=? AND ticket_type=? AND environment=? AND id<>? AND (state='PAID' OR (state='PAID_REVIEW' AND provider NOT IN ('manual','form')) OR (state IN ('CREATING','CREATED','PENDING','AWAITING_PROOF','PENDING_REVIEW','FORM_PENDING') AND expires_at>?))");$s->execute([$event,$type,$environment,$except,time()]);return (int)$s->fetchColumn();
}
function az_gateway(string $path,string $method='GET',?array $body=null): array {
 $c=az_config();$base='https://api.razorpay.com/v1';if(getenv('ANAZORI_TEST_MODE')==='1'&&getenv('ANAZORI_TEST_GATEWAY')){if(!preg_match('#^http://127\.0\.0\.1:\d+$#',getenv('ANAZORI_TEST_GATEWAY')))throw new RuntimeException('Invalid test gateway.');$base=getenv('ANAZORI_TEST_GATEWAY');}
 return az_http($base.$path,$method,$body,[$c['razorpay_key_id'],$c['razorpay_key_secret']],['Content-Type: application/json']);
}
function az_create_order(array $u,string $slug,string $typeId,int $quantity,array $answers,string $methodId='',string $gameId=''): array {
 return az_create_manual_order($u,$slug,$typeId,$quantity,$answers,$methodId,$gameId);
}
/** Kept for historical gateway reconciliation tests; public checkout never calls this. */
function az_create_legacy_order(array $u,string $slug,string $typeId,int $quantity,array $answers): array {
 if(!$u['email_verified'])throw new RuntimeException('Verify your email before registering.');if($quantity<1||$quantity>10)throw new RuntimeException('Choose between 1 and 10 passes.');az_limit('checkout',$u['id'].'',20,900);
 $db=cms_db();$db->beginTransaction();try{az_lock($db);$event=az_event($slug);if(!$event||cms_event_phase($event['fields'])!=='open')throw new RuntimeException('Registration is not open for this event.');$f=$event['fields'];$type=null;foreach(az_prices($f) as $t)if($t['id']===$typeId&&$t['active'])$type=$t;if(!$type)throw new RuntimeException('This ticket type is unavailable.');
  $environment=$type['price']===0?'live':az_config()['payment_mode'];if($type['price']>0&&!az_payment_ready())throw new RuntimeException('Online payments are not available yet. Please contact the organisers.');
  if($type['capacity']>0&&az_reserved((int)$event['id'],$typeId,$environment)+$quantity>$type['capacity'])throw new RuntimeException('There are not enough passes remaining. Choose a smaller quantity or another type.');
  $validated=[];foreach(cms_questions($f) as $i=>$question){$a=$answers[$i]??'';if(!is_string($a)||trim($a)===''||mb_strlen($a)>2000||str_contains($a,"\0"))throw new RuntimeException('Answer all event questions.');$validated[$question]=trim($a);}foreach(['college'=>'College / organisation','phone'=>'Contact number'] as $key=>$label){$a=$answers[$key]??'';if(!is_string($a)||mb_strlen(trim($a))<2||mb_strlen($a)>160||str_contains($a,"\0"))throw new RuntimeException('Enter your '.$label.'.');if($key==='phone'&&(!preg_match('/^\+?[0-9 ()-]{10,20}$/',$a)||strlen(preg_replace('/\D/','',$a))<10))throw new RuntimeException('Enter a valid contact number.');$validated[$label]=trim($a);}
  $amount=$type['price']*$quantity;$snapshot=['title'=>$event['title'],'type'=>$type['label'],'starts_at'=>$f['starts_at'],'ends_at'=>$f['ends_at'],'venue'=>$f['venue']?:setting('venue'),'rules_pdf'=>$f['rules_pdf'],'name'=>$u['name'],'email'=>$u['email']];$now=gmdate('c');$public='ORDER-'.strtoupper(bin2hex(random_bytes(8)));
  $db->prepare('INSERT INTO az_orders(public_id,participant_id,event_id,event_slug,ticket_type,snapshot,answers,quantity,unit_price,amount,state,environment,provider,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')->execute([$public,$u['id'],$event['id'],$slug,$typeId,json_encode($snapshot),json_encode($validated),$quantity,$type['price'],$amount,$amount===0?'PAID':'CREATING',$environment,$amount===0?'free':'phonepe',time()+900,$now,$now]);$id=(int)$db->lastInsertId();if($amount===0)az_issue_tickets(az_order($id));$db->commit();
 }catch(Throwable $e){if($db->inTransaction())$db->rollBack();throw $e;}
 if($amount>0)try{az_phonepe_create(az_order($id));}
 // A timeout may occur after PhonePe accepted the order. Keep it reconcilable,
 // rather than announcing failure and encouraging a duplicate payment.
 catch(Throwable $e){$db->prepare("UPDATE az_orders SET state='PENDING',provider_state='create_uncertain',updated_at=? WHERE id=? AND state='CREATING'")->execute([gmdate('c'),$id]);error_log('Anazori PhonePe checkout creation needs reconciliation.');}
 return az_order($id);
}
function az_issue_tickets(array $order): void {
 if(az_participation_mode(['slug'=>$order['event_slug']??''])==='contribution')return;
 $db=cms_db();$s=$db->prepare('SELECT COUNT(*) FROM az_tickets WHERE order_id=?');$s->execute([$order['id']]);if((int)$s->fetchColumn()>0)return;
 $s=$db->prepare('SELECT o.snapshot FROM az_tickets t JOIN az_orders o ON o.id=t.order_id WHERE t.participant_id=? AND o.event_id=? AND o.environment=?');$s->execute([$order['participant_id'],$order['event_id'],$order['environment']]);
 $game=json_decode($order['snapshot'],true)['game_id']??'';
 foreach($s as $previous){$previousGame=json_decode($previous['snapshot'],true)['game_id']??'';if($order['event_slug']==='joystick'&&$game!==''&&$previousGame!==''&&$game!==$previousGame)continue;throw new RuntimeException('You have already got your ticket for this event. Please reach our team for more details.');}
 for($i=0;$i<1;$i++){$id='AZ16-'.strtoupper(bin2hex(random_bytes(7)));$token=$id.'.'.bin2hex(random_bytes(32));$db->prepare('INSERT INTO az_tickets(ticket_id,order_id,participant_id,event_id,token,created_at) VALUES(?,?,?,?,?,?)')->execute([$id,$order['id'],$order['participant_id'],$order['event_id'],$token,gmdate('c')]);}
 az_notify_order89($order,'ticket_confirmed','',['ticket'=>$id,'path'=>'/ticket.php?id='.$id,'cta'=>'Open your ticket']);
}
/** Staff-triggered reconciliation rechecks grants after the provider fetch, under the write lock. */
function az_payment_actor_order(array $actor,int $orderId): array {
 $actor=st_refresh_user($actor);
 if($actor['must_change_password']||!cms_can($actor,'payments','verify'))throw new RuntimeException('No payment verification access.');
 return st_require_order($actor,$orderId);
}
function az_accept_payment(array $order,array $payment,?array $actor=null): array {
 if(!in_array($order['provider'],['phonepe','razorpay'],true))throw new RuntimeException('This registration requires coordinator payment review.');
 $idPattern=$order['provider']==='phonepe'?'/^[a-zA-Z0-9_-]{1,100}$/':'/^pay_[a-zA-Z0-9]+$/';
 if(($payment['order_id']??'')!==$order['gateway_order']||(int)($payment['amount']??-1)!==(int)$order['amount']||($payment['currency']??'')!=='INR'||!preg_match($idPattern,$payment['id']??'')||!isset($payment['status']))throw new RuntimeException('Payment details do not match this order.');
 $db=cms_db();$nested=$db->inTransaction();$savepoint='az_payment_'.bin2hex(random_bytes(6));if($nested)$db->exec('SAVEPOINT '.$savepoint);else $db->beginTransaction();try{az_lock($db);$current=$actor!==null?az_payment_actor_order($actor,(int)$order['id']):az_order((int)$order['id']);if(!$current)throw new RuntimeException('Order unavailable.');
  if(($payment['order_id']??'')!==$current['gateway_order']||(int)($payment['amount']??-1)!==(int)$current['amount']||($payment['currency']??'')!==$current['currency'])throw new RuntimeException('Payment details changed. Check this order again.');
  if($current['state']==='REFUNDED'){if($nested)$db->exec('RELEASE SAVEPOINT '.$savepoint);else $db->commit();return $current;}if($current['gateway_payment']&&$current['gateway_payment']!==$payment['id']&&$current['state']==='PAID'){if($nested)$db->exec('RELEASE SAVEPOINT '.$savepoint);else $db->commit();return $current;}
  $status=$payment['status'];$refunded=(int)($payment['amount_refunded']??0);$state=$current['state'];
  if($status==='refunded'||($refunded>0&&$refunded>=(int)$current['amount'])){$state='REFUNDED';$db->prepare("UPDATE az_tickets SET status='VOID' WHERE order_id=?")->execute([$current['id']]);}
  elseif($status==='captured'&&($payment['captured']??false)){
   $state='PAID';if(!in_array($current['state'],['PAID','PAID_REVIEW'],true)&&$current['expires_at']<=time()){$event=cms_record((int)$current['event_id']);$type=null;foreach(az_prices($event['fields']??[]) as $t)if($t['id']===$current['ticket_type'])$type=$t;if(!$type||($type['capacity']>0&&az_reserved((int)$current['event_id'],$current['ticket_type'],$current['environment'],(int)$current['id'])+$current['quantity']>$type['capacity']))$state='PAID_REVIEW';}
   if($current['state']==='PAID_REVIEW'){$event=cms_record((int)$current['event_id']);$type=null;foreach(az_prices($event['fields']??[]) as $t)if($t['id']===$current['ticket_type'])$type=$t;if(!$type||($type['capacity']>0&&az_reserved((int)$current['event_id'],$current['ticket_type'],$current['environment'],(int)$current['id'])+$current['quantity']>$type['capacity']))$state='PAID_REVIEW';}
   if($state==='PAID')az_issue_tickets($current);
  }elseif(!in_array($state,['PAID','PAID_REVIEW'],true))$state=$status==='failed'?'FAILED':'PENDING';
  $db->prepare('UPDATE az_orders SET gateway_payment=?,state=?,provider_state=?,updated_at=? WHERE id=?')->execute([$payment['id'],$state,$refunded>0&&$refunded<(int)$current['amount']?'partial_refund':$status,gmdate('c'),$current['id']]);if($nested)$db->exec('RELEASE SAVEPOINT '.$savepoint);else $db->commit();return az_order((int)$current['id']);
 }catch(Throwable $e){if($nested&&$db->inTransaction()){$db->exec('ROLLBACK TO SAVEPOINT '.$savepoint);$db->exec('RELEASE SAVEPOINT '.$savepoint);}elseif($db->inTransaction())$db->rollBack();throw $e;}
}
function az_verify_payment(array $order,string $paymentId,string $signature): array {
 if($order['environment']!==az_config()['payment_mode'])throw new RuntimeException('This order belongs to a different payment environment.');
 if(!preg_match('/^pay_[a-zA-Z0-9]+$/',$paymentId)||!preg_match('/^[a-f0-9]{64}$/',$signature)||!hash_equals(hash_hmac('sha256',$order['gateway_order'].'|'.$paymentId,az_config()['razorpay_key_secret']),$signature))throw new RuntimeException('Payment verification failed. Check your dashboard before retrying.');
 return az_accept_payment($order,az_gateway('/payments/'.rawurlencode($paymentId)));
}
function az_refresh_order(array $order,?array $actor=null): array {
 if($actor!==null)$order=az_payment_actor_order($actor,(int)$order['id']);
 if(($order['provider']??'')==='phonepe')return az_phonepe_refresh($order,$actor);
 if(!$order['gateway_order'])return $order;if($order['environment']!==az_config()['payment_mode'])throw new RuntimeException('Switch the integration to this order’s payment environment to verify it.');
 if($order['gateway_payment'])return az_accept_payment($order,az_gateway('/payments/'.rawurlencode($order['gateway_payment'])),$actor);
 $list=az_gateway('/orders/'.rawurlencode($order['gateway_order']).'/payments');foreach($list['items']??[] as $p)if(in_array($p['status']??'',['captured','refunded'],true))return az_accept_payment($order,$p,$actor);
 if(!empty($list['items']))return az_accept_payment($order,end($list['items']),$actor);return $order;
}
function az_ticket_data(string $id): ?array {$s=cms_db()->prepare('SELECT t.*,o.event_id order_event_id,o.snapshot,o.environment,o.state order_state FROM az_tickets t JOIN az_orders o ON t.order_id=o.id WHERE t.ticket_id=?');$s->execute([$id]);return $s->fetch()?:null;}
function az_scan(string $token,array $staff,bool $commit): array {
 if(!cms_can($staff,'tickets','scan')||$staff['must_change_password'])throw new RuntimeException('No ticket scanner access.');if(!preg_match('/^AZ16-[A-F0-9]{14}\.[a-f0-9]{64}$/',$token))throw new RuntimeException('This is not an Anazori entry pass.');az_limit('scanner',$staff['id'].'',200,60);
 $db=cms_db();$db->beginTransaction();try{az_lock($db);$staff=st_refresh_user($staff);if(!cms_can($staff,'tickets','scan')||$staff['must_change_password'])throw new RuntimeException('No ticket scanner access.');$s=$db->prepare('SELECT t.*,o.event_id order_event_id,o.snapshot,o.state order_state,o.environment FROM az_tickets t JOIN az_orders o ON t.order_id=o.id WHERE t.token=?');$s->execute([$token]);$t=$s->fetch();if(!$t||$t['order_state']!=='PAID')throw new RuntimeException('This ticket is invalid or revoked.');if($t['environment']!=='live')throw new RuntimeException('Test passes cannot enter a live event.');
  st_require_event($staff,(int)$t['order_event_id']);$snapshot=json_decode($t['snapshot'],true);if($t['status']==='BLOCKED')throw new RuntimeException('This ticket is blocked. Contact the event coordinator.');if($t['status']==='VOID')throw new RuntimeException('This ticket has been revoked.');if($commit){if($t['status']!=='VALID')throw new RuntimeException('Already checked in on '.$t['checked_at'].'.');$when=gmdate('c');$s=$db->prepare("UPDATE az_tickets SET status='USED',checked_at=?,checked_by=? WHERE id=? AND status='VALID'");$s->execute([$when,$staff['id'],$t['id']]);if(!$s->rowCount())throw new RuntimeException('Already checked in.');$db->prepare('INSERT INTO az_checkins(ticket_id,staff_id,checked_at) VALUES(?,?,?)')->execute([$t['id'],$staff['id'],$when]);st_event_audit($staff,(int)$t['order_event_id'],'ticket.checkin',$t['ticket_id']);cms_audit($staff,'ticket.checkin',$t['ticket_id']);$t['status']='USED';$t['checked_at']=$when;}$db->commit();return ['ticket_id'=>$t['ticket_id'],'name'=>($snapshot['registration_kind']??'individual')==='team'?($snapshot['team_name']??$snapshot['name']):$snapshot['name'],'team_lead'=>$snapshot['name'],'registration_kind'=>$snapshot['registration_kind']??'individual','event'=>$snapshot['title'],'type'=>($snapshot['game']??'')?($snapshot['game'].' · '.$snapshot['type']):$snapshot['type'],'game'=>$snapshot['game']??'','game_id'=>$snapshot['game_id']??'','status'=>$t['status'],'checked_at'=>$t['checked_at'],'environment'=>$t['environment']];
 }catch(Throwable $e){if($db->inTransaction())$db->rollBack();throw $e;}
}
