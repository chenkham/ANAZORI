<?php
require_once __DIR__.'/includes/commerce.php';
set_security_headers();
header('Cache-Control: private, no-store');
$staff=cms_require_user();
if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);header('Allow: POST');exit('Method not allowed.');}
$eventId=filter_input(INPUT_POST,'event_id',FILTER_VALIDATE_INT)?:0;
$return='/admin.php?section=certificates'.($eventId>0?'&event_id='.$eventId:'');
try {
    az_csrf();
    $person=is_string($_POST['person']??null)?$_POST['person']:'';
    $certificateId=az_certificate_issue_staff($staff,$eventId,$person);
    $query=cms_db()->prepare('SELECT id FROM az_certificates WHERE certificate_id=?');
    $query->execute([$certificateId]);
    $rowId=(int)$query->fetchColumn();
    if($rowId<1) throw new RuntimeException('The certificate could not be opened.');
    cms_flash('Teacher coordinator certificate issued. You can preview or download it here.');
    header('Location: /certificate-preview.php?certificate_row_id='.$rowId,true,303);
    exit;
} catch(Throwable $error) {
    cms_flash($error->getMessage(),'error');
    header('Location: '.$return,true,303);
    exit;
}
