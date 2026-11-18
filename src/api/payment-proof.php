<?php
require_once __DIR__.'/../includes/commerce.php';
set_security_headers();header('Cache-Control: no-store');
$public=is_string($_POST['order']??null)?$_POST['order']:'';
try{
    if($_SERVER['REQUEST_METHOD']!=='POST')throw new RuntimeException('Use POST.');
    az_csrf();$participant=az_participant();
    if(!$participant)throw new RuntimeException('Sign in before uploading.');
    az_submit_payment_proof($participant,$public,$_POST,$_FILES['proof']??[]);
    $_SESSION['payment_proof_flash']=['message'=>'Screenshot submitted. The coordinator will review your payment.','error'=>false];
}catch(Throwable $error){
    $_SESSION['payment_proof_flash']=['message'=>$error instanceof PDOException?'The screenshot could not be submitted. Please reload and try again.':$error->getMessage(),'error'=>true];
}
$url=preg_match('/^ORDER-[A-F0-9]{16}$/D',$public)?'/payment-proof.php?order='.rawurlencode($public):'/dashboard.php';
header('Location: '.$url,true,303);
