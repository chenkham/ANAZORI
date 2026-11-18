<?php
require_once __DIR__.'/../includes/commerce.php';set_security_headers();header('Content-Type: application/json');header('Cache-Control: no-store');
try{
    if($_SERVER['REQUEST_METHOD']!=='POST')throw new RuntimeException('Use POST.');az_csrf();$participant=az_participant();
    if(!$participant)throw new RuntimeException('Sign in to save your progress.');
    if((int)($_SERVER['CONTENT_LENGTH']??0)>65*1024*1024)throw new RuntimeException('Use at most 60 MB of attachments.');
    $event=az_event(cms_text('event',100));if(!$event)throw new RuntimeException('Event unavailable.');
    $result=az_save_checkout_draft($participant,$event,$_POST,$_FILES['uploads']??[]);echo json_encode(['ok'=>true,...$result]);
}catch(Throwable $error){http_response_code($error instanceof PDOException?503:400);echo json_encode(['ok'=>false,'error'=>$error instanceof PDOException?'Your progress could not be saved. Please retry.':$error->getMessage()]);}
