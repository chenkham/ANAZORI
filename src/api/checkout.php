<?php
require_once __DIR__.'/../includes/commerce.php';
set_security_headers();header('Cache-Control: no-store');
$native=($_POST['response_format']??'')==='redirect';
if(!$native)header('Content-Type: application/json');
try{
    if($_SERVER['REQUEST_METHOD']!=='POST')throw new RuntimeException('Use POST.');
    if((int)($_SERVER['CONTENT_LENGTH']??0)>65*1024*1024)throw new RuntimeException('The response is too large. Upload at most 60 MB of files in total.');
    az_csrf();$participant=az_participant();
    if(!$participant)throw new RuntimeException('Sign in before registering.');
    if(empty($participant['profile_completed']))throw new RuntimeException('Enter your full name in your profile before registering.');
    if(($_POST['consent']??'')!=='yes')throw new RuntimeException('Agree to the event rules before continuing.');
    $nonce=cms_text('nonce',64);
    if(!isset($_SESSION['checkout_nonces'][$nonce]))throw new RuntimeException('Reload checkout and try again.');
    $previous=$_SESSION['checkout_nonces'][$nonce];
    if(is_int($previous)){
        $order=az_order($previous);
        if(!$order||(int)$order['participant_id']!==(int)$participant['id'])throw new RuntimeException('Registration unavailable.');
    }else{
        $quantity=filter_var($_POST['quantity']??null,FILTER_VALIDATE_INT);
        if($quantity===false||$quantity===null)throw new InvalidArgumentException('Choose a whole number of passes.');
        $answers=is_array($_POST['answers']??null)?$_POST['answers']:[];
        $event=az_event(cms_text('event',100));
        if($event&&!empty($event['fields']['form_workflow']))$order=az_create_form_order($participant,$event['slug'],cms_text('type',60),$quantity,$answers,$_FILES['uploads']??[],cms_text('game',60),(int)($_POST['edit_order']??0),(int)($_POST['form_revision']??0),cms_text('team_name',120));
        else $order=az_create_order($participant,cms_text('event',100),cms_text('type',60),$quantity,$answers,cms_text('payment_method',60),cms_text('game',60));
        $_SESSION['checkout_nonces'][$nonce]=(int)$order['id'];
    }
    $url=$order['provider']==='manual'?'/payment-proof.php?order='.rawurlencode($order['public_id']):'/dashboard.php';
    if($native){header('Location: '.$url,true,303);exit;}
    echo json_encode(['ok'=>true,'order'=>$order['public_id'],'state'=>$order['state'],'amount'=>(int)$order['amount'],'url'=>$url]);
}catch(Throwable $error){
    $message=$error instanceof PDOException?'Registration could not be completed. Please try again.':$error->getMessage();
    if($native){
        $_SESSION['checkout_error']=$message;
        $slug=is_string($_POST['event']??null)&&preg_match('/^[a-z0-9-]{1,100}$/D',$_POST['event'])?$_POST['event']:'';
        $game=is_string($_POST['game']??null)&&preg_match('/^[a-z0-9-]{1,60}$/D',$_POST['game'])?$_POST['game']:'';
        header('Location: /checkout.php?event='.rawurlencode($slug).($game?'&game='.rawurlencode($game):''),true,303);exit;
    }
    http_response_code(400);echo json_encode(['ok'=>false,'error'=>$message]);
}
