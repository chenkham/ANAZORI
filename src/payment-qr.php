<?php
declare(strict_types=1);
require_once __DIR__.'/includes/commerce.php';
set_security_headers();header('Cache-Control: private, no-store');
try{
    if(($_SERVER['REQUEST_METHOD']??'')!=='GET')throw new RuntimeException('Payment QR unavailable.');
    $person=az_participant();$staff=cms_user();$slug=is_string($_GET['event']??null)?$_GET['event']:'';$orderId=is_string($_GET['order']??null)?$_GET['order']:'';
    $type=is_string($_GET['type']??null)?$_GET['type']:'';$game=is_string($_GET['game']??null)?$_GET['game']:'';
    if($orderId!==''){
        $order=az_order_public($orderId);if(!$order)throw new RuntimeException('Payment QR unavailable.');
        $own=$person&&(int)$person['id']===(int)$order['participant_id'];
        $canReview=$staff&&!$staff['must_change_password']&&cms_can($staff,'payments','view')&&st_can_event($staff,(int)$order['event_id']);
        if(!$own&&!$canReview)throw new RuntimeException('Payment QR unavailable.');
        $snapshot=json_decode($order['snapshot'],true);$field=$snapshot['ticket_payment']??[];
        if(empty($field['payment_dynamic']))throw new RuntimeException('Payment QR unavailable.');
        $amount=(int)$order['amount'];$reference=$order['public_id'];
    }else{
        if(!$person||!$person['email_verified']||!$person['profile_completed'])throw new RuntimeException('Payment QR unavailable.');
        $event=az_event($slug);if(!$event)throw new RuntimeException('Payment QR unavailable.');
        [$fields]=az_draft_context($person,$event,0,$game);az_require_internal_registration97($fields,$game);
        $ticket=az_registration_entry($fields,$game,$type);$field=az_ticket_qrs85($fields)[$type]??[];
        if(!$ticket||empty($field['payment_dynamic']))throw new RuntimeException('Payment QR unavailable.');
        $draft=az_checkout_draft((int)$person['id'],(int)$event['id'],az_draft_context81($game));
        $reference=(json_decode($draft['state_json']??'{}',true)?:[])['payment_reference']??'';$amount=(int)$ticket['price'];
    }
    $uri=az_payment_uri108($field['payment_upi']??'',$field['payment_name']??'Anazori',$amount,$reference);
    $options=new chillerlan\QRCode\QROptions(['outputType'=>chillerlan\QRCode\QRCode::OUTPUT_MARKUP_SVG,'outputBase64'=>false,'eccLevel'=>chillerlan\QRCode\QRCode::ECC_M,'svgAddXmlHeader'=>false,'drawLightModules'=>true,'addQuietzone'=>true,'quietzoneSize'=>4]);
    header('Content-Type: image/svg+xml; charset=UTF-8');header("Content-Security-Policy: default-src 'none'; sandbox");
    echo (new chillerlan\QRCode\QRCode($options))->render($uri);
}catch(Throwable){http_response_code(404);header('Content-Type: text/plain; charset=UTF-8');echo 'Payment QR unavailable. Reload the registration form and choose a paid ticket.';}
