<?php
require_once __DIR__.'/../includes/commerce.php';cms_db();header('Content-Type: application/json');header('Cache-Control: no-store');
if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo '{"ok":false}';exit;}
if(!az_phonepe_webhook_auth($_SERVER['HTTP_AUTHORIZATION']??$_SERVER['REDIRECT_HTTP_AUTHORIZATION']??'')){http_response_code(401);echo '{"ok":false}';exit;}
$raw=file_get_contents('php://input',false,null,0,262145);if(strlen($raw)>262144){http_response_code(413);echo '{"ok":false}';exit;}
try{
 $delivery=json_decode($raw,true,64,JSON_THROW_ON_ERROR);$event=$delivery['event']??'';
 if(!in_array($event,['checkout.order.completed','checkout.order.failed','pg.refund.completed','pg.refund.failed'],true)){echo '{"ok":true}';exit;}
 $payload=$delivery['payload']??null;$merchantId=is_array($payload)?($payload['merchantOrderId']??$payload['originalMerchantOrderId']??''):'';
 if(!is_string($merchantId)||!preg_match('/^ORDER-[A-F0-9]{16}$/',$merchantId))throw new InvalidArgumentException('Invalid merchant order.');
 $order=az_order_public($merchantId);if(!$order){echo '{"ok":true}';exit;}
 if($order['provider']!=='phonepe'||$order['environment']!==az_config()['payment_mode'])throw new InvalidArgumentException('Invalid payment environment.');
 if(str_starts_with($event,'checkout.order.')){
  if(($order['gateway_order']&&($payload['orderId']??'')!==$order['gateway_order'])||!az_phonepe_amount_matches($payload['amount']??null,(int)$order['amount']))throw new InvalidArgumentException('Invalid payment details.');
  // Authenticate the delivery, then independently fetch PhonePe's authoritative status.
  $order=az_phonepe_refresh($order);
  if($event==='checkout.order.completed'&&!in_array($order['state'],['PAID','PAID_REVIEW','REFUNDED'],true))throw new RuntimeException('Status not yet confirmed.');
 }elseif($event==='pg.refund.completed'){az_phonepe_refund($order,$payload);}
 $id='phonepe:'.hash('sha256',$order['environment'].'|'.$raw);
 try{cms_db()->prepare('INSERT INTO az_webhooks(event_id,received_at) VALUES(?,?)')->execute([$id,gmdate('c')]);}catch(PDOException $e){$s=cms_db()->prepare('SELECT event_id FROM az_webhooks WHERE event_id=?');$s->execute([$id]);if(!$s->fetch())throw $e;}
 echo '{"ok":true}';
}catch(InvalidArgumentException|JsonException $e){http_response_code(400);echo '{"ok":false}';}catch(Throwable $e){http_response_code(503);echo '{"ok":false}';}
