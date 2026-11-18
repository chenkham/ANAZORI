<?php
declare(strict_types=1);
require_once __DIR__.'/../includes/commerce.php';
set_security_headers();header('Content-Type: application/json');header('Cache-Control: no-store');
try{
    if($_SERVER['REQUEST_METHOD']!=='POST')throw new RuntimeException('Use POST.');az_csrf();$staff=cms_user();
    if(!$staff||$staff['must_change_password'])throw new RuntimeException('Sign in to Studio.');
    $record=cms_record((int)($_POST['event_id']??0));
    if(!$record||$record['type']!=='event'||!cms_can($staff,'event','edit',$record))throw new RuntimeException('No access to edit this event.');
    $id=cms_upload($staff,$_FILES['file']??[]);$q=cms_db()->prepare('SELECT path,title,mime FROM cms_media WHERE id=?');$q->execute([$id]);
    echo json_encode(['ok'=>true,'media'=>$q->fetch()]);
}catch(Throwable $error){http_response_code(400);echo json_encode(['ok'=>false,'error'=>$error instanceof PDOException?'Upload unavailable.':$error->getMessage()]);}
