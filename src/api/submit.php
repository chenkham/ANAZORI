<?php
declare(strict_types=1);
require_once __DIR__.'/../config/security.php';
set_security_headers();header('Content-Type: application/json; charset=utf-8');
if (($_SERVER['REQUEST_METHOD']??'')!=='POST') {header('Allow: POST');http_response_code(405);echo json_encode(['success'=>false,'error'=>'Use the current event page.']);exit;}
http_response_code(409);
echo json_encode(['success'=>false,'error'=>'This older form is no longer accepting submissions. Please use the current event page to register.','url'=>'/events.php']);
