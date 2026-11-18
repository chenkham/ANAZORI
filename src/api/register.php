<?php
declare(strict_types=1);
require_once __DIR__.'/../config/security.php';
set_security_headers();header('Content-Type: application/json; charset=utf-8');
http_response_code(410);
echo json_encode(['success'=>false,'error'=>'This older registration form has been retired. Please use the current event page.','url'=>'/events.php']);
