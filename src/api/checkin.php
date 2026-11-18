<?php
require_once __DIR__.'/../includes/commerce.php';set_security_headers();header('Content-Type: application/json');header('Cache-Control: no-store');
try{if($_SERVER['REQUEST_METHOD']!=='POST')throw new RuntimeException('Use POST.');az_csrf();$u=cms_user();if(!$u)throw new RuntimeException('Staff sign-in required.');echo json_encode(['ok'=>true,'ticket'=>az_scan(cms_text('token',140),$u,($_POST['action']??'')==='checkin')]);}
catch(Throwable $e){http_response_code(409);echo json_encode(['ok'=>false,'error'=>$e instanceof PDOException?'Check-in could not be completed. Please retry.':$e->getMessage()]);}
