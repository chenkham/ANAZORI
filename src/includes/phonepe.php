<?php
declare(strict_types=1);

function az_phonepe_base(): string {
    $c=az_config();
    if(!in_array($c['payment_mode'],['test','live'],true))throw new RuntimeException('Invalid PhonePe environment. Use sandbox or production.');
    $fixture=getenv('ANAZORI_TEST_GATEWAY');
    if(getenv('ANAZORI_TEST_MODE')==='1'&&$fixture){
        if($c['payment_mode']!=='test'||!preg_match('#^http://127\.0\.0\.1:\d+$#',$fixture))throw new RuntimeException('Invalid test gateway.');
        return $fixture;
    }
    return $c['payment_mode']==='live'?'https://api.phonepe.com/apis/pg':'https://api-preprod.phonepe.com/apis/pg-sandbox';
}

function az_phonepe_token(): string {
    $c=az_config();
    if(!az_phonepe_configured($c))throw new RuntimeException('PhonePe is not configured for this payment environment.');
    $key='phonepe_token_'.$c['payment_mode'];
    $fingerprint=hash('sha256',$c['phonepe_client_id'].'|'.$c['phonepe_client_version'].'|'.$c['phonepe_client_secret'].'|'.az_phonepe_base());
    $s=cms_db()->prepare('SELECT value FROM cms_settings WHERE setting_key=?');$s->execute([$key]);$stored=$s->fetchColumn();
    if($stored){$cached=json_decode(az_decrypt($stored),true);if(($cached['fingerprint']??'')===$fingerprint&&($cached['expires_at']??0)>time()+60)return $cached['token'];}
    $base=az_phonepe_base();
    $url=$c['payment_mode']==='live'?'https://api.phonepe.com/apis/identity-manager/v1/oauth/token':$base.'/v1/oauth/token';
    $response=az_http($url,'FORM',['client_id'=>$c['phonepe_client_id'],'client_version'=>$c['phonepe_client_version'],'client_secret'=>$c['phonepe_client_secret'],'grant_type'=>'client_credentials'],null,['Content-Type: application/x-www-form-urlencoded']);
    $token=$response['access_token']??null;$expires=$response['expires_at']??0;
    if(!is_string($token)||$token===''||preg_match('/[\r\n]/',$token)||($response['token_type']??'')!=='O-Bearer'||!is_numeric($expires)||(int)$expires<=time())throw new RuntimeException('PhonePe authentication could not be completed.');
    cms_put_setting($key,az_encrypt(json_encode(['fingerprint'=>$fingerprint,'token'=>$token,'expires_at'=>(int)$expires],JSON_THROW_ON_ERROR)));
    return $token;
}

function az_phonepe_api(string $path,string $method='GET',?array $body=null): array {
    return az_http(az_phonepe_base().$path,$method,$body,null,['Content-Type: application/json','Authorization: O-Bearer '.az_phonepe_token()]);
}

function az_phonepe_url(string $url): bool {
    $parts=parse_url($url);if(!$parts||isset($parts['user'])||isset($parts['pass'])||isset($parts['fragment']))return false;
    if(($parts['scheme']??'')==='https'&&!isset($parts['port'])&&preg_match('/^(?:[a-z0-9-]+\.)+phonepe\.com$/i',$parts['host']??''))return true;
    // The test double can only redirect into the isolated local test server.
    return getenv('ANAZORI_TEST_MODE')==='1'&&($parts['scheme']??'')==='http'&&($parts['host']??'')==='127.0.0.1'&&str_starts_with($url,az_origin().'/tests-phonepe-checkout?');
}

function az_phonepe_create(array $order): void {
    $remaining=(int)$order['expires_at']-time();
    if($remaining<300)throw new RuntimeException('This reservation expired. Start a new registration.');
    $answers=json_decode($order['answers'],true)?:[];
    $request=[
        'merchantOrderId'=>$order['public_id'],
        'amount'=>(int)$order['amount'], // Stored in integer paise after parsing the studio INR fee.
        'expireAfter'=>min(900,$remaining),
        'paymentFlow'=>[
            'type'=>'PG_CHECKOUT',
            'merchantUrls'=>['redirectUrl'=>az_origin().'/payment-return.php?order='.rawurlencode($order['public_id'])],
            'paymentModeConfig'=>[
                'version'=>'V2',
                'enabledPaymentModes'=>[['type'=>'UPI','flows'=>['INTENT','QR','COLLECT'],'instruments'=>['BANK_ACCOUNT']]],
            ],
        ],
        'metaInfo'=>['udf1'=>$order['public_id']],
    ];
    $phone=preg_replace('/\D/','',(string)($answers['Contact number']??''));
    if(strlen($phone)===10)$request['prefillUserLoginDetails']=['phoneNumber'=>'+91'.$phone];
    $remote=az_phonepe_api('/checkout/v2/pay','POST',$request);
    $id=$remote['orderId']??'';$url=$remote['redirectUrl']??'';$expire=$remote['expireAt']??0;
    if(!is_string($id)||!preg_match('/^[a-zA-Z0-9_-]{1,100}$/',$id)||($remote['state']??'')!=='PENDING'||!is_string($url)||!az_phonepe_url($url)||!is_numeric($expire)||(int)$expire<=time()*1000)throw new RuntimeException('PhonePe could not create a valid checkout session.');
    cms_db()->prepare("UPDATE az_orders SET gateway_order=?,checkout_url=?,state='CREATED',expires_at=?,updated_at=? WHERE id=? AND state='CREATING'")->execute([$id,az_encrypt($url),min((int)$order['expires_at'],(int)floor((int)$expire/1000)),gmdate('c'),$order['id']]);
}

function az_phonepe_refresh(array $order,?array $actor=null): array {
    if($order['state']==='REFUNDED')return $order;
    if($order['environment']!==az_config()['payment_mode'])throw new RuntimeException('Switch to this order’s payment environment before checking it.');
    $remote=az_phonepe_api('/checkout/v2/order/'.rawurlencode($order['public_id']).'/status?details=true');
    $remoteId=$remote['orderId']??'';
    if(!is_string($remoteId)||!preg_match('/^[a-zA-Z0-9_-]{1,100}$/',$remoteId)||($order['gateway_order']&&$remoteId!==$order['gateway_order'])||!az_phonepe_amount_matches($remote['amount']??null,(int)$order['amount'])||($remote['currency']??'INR')!=='INR'||(isset($remote['merchantOrderId'])&&$remote['merchantOrderId']!==$order['public_id']))throw new RuntimeException('PhonePe payment details do not match this registration.');
    $state=$remote['state']??'';
    if(!in_array($state,['COMPLETED','PENDING','FAILED'],true))throw new RuntimeException('PhonePe returned an unknown payment state.');
    $payment=null;
    if($state==='COMPLETED')foreach($remote['paymentDetails']??[] as $attempt)if(($attempt['state']??'')==='COMPLETED'){
        if(!in_array($attempt['paymentMode']??'',['UPI_INTENT','UPI_QR','UPI_COLLECT'],true)||!az_phonepe_amount_matches($attempt['amount']??null,(int)$order['amount'])||($attempt['rail']['type']??'UPI')!=='UPI'||($attempt['instrument']['type']??'ACCOUNT')!=='ACCOUNT')throw new RuntimeException('Only a verified UPI bank-account payment can confirm this registration.');
        foreach($attempt['splitInstruments']??[] as $part)if(($part['instrument']['type']??'ACCOUNT')!=='ACCOUNT'||($part['rail']['type']??'UPI')!=='UPI')throw new RuntimeException('Unsupported payment instrument.');
        if($payment!==null)throw new RuntimeException('Multiple completed payments need organiser review.');
        $payment=$attempt;
    }
    if($state==='COMPLETED'&&(!$payment||!is_string($payment['transactionId']??null)||!preg_match('/^[a-zA-Z0-9_-]{1,100}$/',$payment['transactionId'])))throw new RuntimeException('PhonePe has not supplied the completed transaction details yet. Check payment status again.');
    // Fetch the provider before taking the lock; every local write then rechecks current staff access.
    $db=cms_db();$db->beginTransaction();try{
        az_lock($db);$current=$actor!==null?az_payment_actor_order($actor,(int)$order['id']):az_order((int)$order['id']);
        if(!$current||$current['provider']!=='phonepe'||($current['gateway_order']&&$current['gateway_order']!==$remoteId)||!az_phonepe_amount_matches($remote['amount']??null,(int)$current['amount'])||$current['public_id']!==$order['public_id'])throw new RuntimeException('Payment reference changed. Check payment status again.');
        if($current['state']==='REFUNDED'){$db->commit();return $current;}
        if(!$current['gateway_order']){$db->prepare('UPDATE az_orders SET gateway_order=? WHERE id=? AND gateway_order IS NULL')->execute([$remoteId,$current['id']]);$current=az_order((int)$current['id']);}
        if($state!=='COMPLETED'){
            $db->prepare("UPDATE az_orders SET state=?,provider_state=?,updated_at=? WHERE id=? AND state NOT IN ('PAID','PAID_REVIEW','REFUNDED')")->execute([$state==='FAILED'?'FAILED':'PENDING',$state,gmdate('c'),$current['id']]);
            $db->commit();return az_order((int)$current['id']);
        }
        $s=$db->prepare('SELECT COALESCE(SUM(amount),0) FROM az_refunds WHERE order_id=?');$s->execute([$current['id']]);
        $result=az_accept_payment($current,['id'=>$payment['transactionId'],'order_id'=>$remoteId,'amount'=>(int)$current['amount'],'currency'=>'INR','status'=>'captured','captured'=>true,'amount_refunded'=>(int)$s->fetchColumn()],$actor);
        $db->commit();return $result;
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
}

function az_phonepe_amount_matches(mixed $value,int $amount): bool {
    return (is_int($value)||(is_string($value)&&ctype_digit($value)))&&(int)$value===$amount;
}

function az_checkout_response(array $order): array {
    $data=['order'=>$order['public_id'],'amount'=>(int)$order['amount'],'currency'=>$order['currency'],'state'=>$order['state'],'environment'=>$order['environment'],'provider'=>$order['provider'],'checkout_url'=>null];
    if($order['provider']==='phonepe'&&in_array($order['state'],['CREATED','PENDING'],true)&&$order['expires_at']>time()&&$order['checkout_url']&&$order['environment']===az_config()['payment_mode']&&az_payment_ready()){
        $url=az_decrypt($order['checkout_url']);if(!az_phonepe_url($url))throw new RuntimeException('Invalid checkout URL.');$data['checkout_url']=$url;
    }
    return $data;
}

function az_phonepe_webhook_auth(string $authorization): bool {
    $c=az_config();
    return az_phonepe_configured($c)&&hash_equals(hash('sha256',$c['phonepe_webhook_username'].':'.$c['phonepe_webhook_password']),$authorization);
}

function az_phonepe_refund(array $order,array $payload): void {
    $merchantRefund=$payload['merchantRefundId']??'';
    if(!is_string($merchantRefund)||!preg_match('/^[a-zA-Z0-9_-]{1,63}$/',$merchantRefund))throw new RuntimeException('Missing merchant refund reference.');
    if($order['environment']!==az_config()['payment_mode'])throw new RuntimeException('Wrong payment environment.');
    $refund=az_phonepe_api('/payments/v2/refund/'.rawurlencode($merchantRefund).'/status');
    $amount=$refund['amount']??null;$id=$refund['refundId']??'';
    if(($refund['originalMerchantOrderId']??'')!==$order['public_id']||!is_string($id)||!preg_match('/^[a-zA-Z0-9_-]{1,90}$/',$id)||!az_phonepe_amount_matches($amount,(int)($payload['amount']??-1))||(int)$amount<1||(int)$amount>(int)$order['amount']||$id!==($payload['refundId']??''))throw new RuntimeException('Refund details do not match.');
    if(($refund['state']??'')!=='COMPLETED')throw new RuntimeException('Refund is not confirmed yet.');
    $db=cms_db();$db->beginTransaction();try{
        az_lock($db);$key='phonepe:'.$id;$s=$db->prepare('SELECT * FROM az_refunds WHERE refund_id=?');$s->execute([$key]);$previous=$s->fetch();
        if($previous&&((int)$previous['order_id']!==(int)$order['id']||(int)$previous['amount']!==(int)$amount))throw new RuntimeException('Refund already belongs to another registration.');
        if(!$previous)$db->prepare('INSERT INTO az_refunds(refund_id,order_id,amount,received_at) VALUES(?,?,?,?)')->execute([$key,$order['id'],(int)$amount,gmdate('c')]);
        $s=$db->prepare('SELECT SUM(amount) FROM az_refunds WHERE order_id=?');$s->execute([$order['id']]);$total=(int)$s->fetchColumn();
        if($total>(int)$order['amount'])throw new RuntimeException('Refund total exceeds the original payment.');
        if($total===(int)$order['amount']){
            $db->prepare("UPDATE az_orders SET state='REFUNDED',provider_state='refunded',updated_at=? WHERE id=?")->execute([gmdate('c'),$order['id']]);
            $db->prepare("UPDATE az_tickets SET status='VOID' WHERE order_id=?")->execute([$order['id']]);
        }else $db->prepare("UPDATE az_orders SET provider_state='partial_refund',updated_at=? WHERE id=?")->execute([gmdate('c'),$order['id']]);
        $db->commit();
    }catch(Throwable $e){if($db->inTransaction())$db->rollBack();throw $e;}
}
